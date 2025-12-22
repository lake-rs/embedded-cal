#![no_std]

use stm32_metapac::{hash, rcc};

const SHA256_BLOCK_SIZE: usize = 64;
const WORD_SIZE: usize = 4;
const CSR_REGS_LEN: usize = 54;

pub struct Stm32wba55 {
    hash: hash::Hash,
}

impl Stm32wba55 {
    pub fn new(hash: hash::Hash, rcc: &rcc::Rcc) -> Self {
        // Enable HASH clock
        rcc.ahb2enr().modify(|w| w.set_hashen(true));

        Self { hash }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            -16 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

pub struct HashState {
    algorithm: HashAlgorithm,

    /// HASH context swap registers (HASH_CSR0 - HASH_CSR53)
    csr: [u32; CSR_REGS_LEN],
    /// HASH start register (HASH_STR)
    str: hash::regs::Str,
    /// HASH interrupt enable register (HASH_IMR)
    imr: hash::regs::Imr,
    /// HASH control register (HASH_CR)
    cr: hash::regs::Cr,

    /// Buffer for pending input. SHA-256 requires feeding complete NBWE-sized
    /// blocks to the hardware, so this stores leftover bytes when the caller
    /// provides data that does not align to a full block.
    block: [u8; SHA256_BLOCK_SIZE + WORD_SIZE],

    /// Number of bytes currently stored in `block`.
    block_bytes_used: usize,

    /// Indicates whether the next block to process is the first SHA-256 block.
    first_block: bool,
}

pub enum HashResult {
    Sha256([u8; 32]),
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
        }
    }
}

impl embedded_cal::HashProvider for Stm32wba55 {
    type Algorithm = HashAlgorithm;
    type HashState = HashState;
    type HashResult = HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        Self::HashState {
            algorithm: algorithm,
            csr: [0; CSR_REGS_LEN],
            str: hash::regs::Str(0),
            imr: hash::regs::Imr(0),
            cr: hash::regs::Cr(0),
            block: [0; SHA256_BLOCK_SIZE + WORD_SIZE],
            block_bytes_used: 0,
            first_block: true,
        }
    }

    fn update(&mut self, instance: &mut HashState, data: &[u8]) {
        // Reinitialize the HASH peripheral before processing new input
        self.hash.cr().write(|w| w.set_init(true));
        while self.hash.cr().read().init() {}
        self.configure_and_reset_context(instance.algorithm);

        // Restore the previously saved intermediate state for non-initial blocks.
        if !instance.first_block {
            self.restore_context(&instance);
        }

        // Hardware can only pause hashing after exactly NBWE (Number of words expected) words have been written.
        // For SHA-256 this corresponds to 17 words for the first block, and 16 words for all subsequent blocks.
        // Equivalent value available at: self.hash.sr().read().nbwe().bits()
        let block_size = SHA256_BLOCK_SIZE + if instance.first_block { WORD_SIZE } else { 0 };

        // Case 1: the provided data fits entirely in the current partial block.
        // Buffer it and return, leaving the block incomplete for later continuation.
        if data.len() < (block_size - instance.block_bytes_used) {
            instance.block[instance.block_bytes_used..instance.block_bytes_used + data.len()]
                .copy_from_slice(data);
            instance.block_bytes_used += data.len();

            return;
        }

        // Case 2: the incoming data exceeds the remaining space in the current block.
        // First, fill the block + data until one full block.
        let data_bytes_used = block_size - instance.block_bytes_used;

        instance.block[instance.block_bytes_used..block_size]
            .copy_from_slice(&data[..data_bytes_used]);

        for chunk in instance.block[..block_size].chunks_exact(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes.copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash.din().write_value(word);
        }

        // Still on case 2, if data left doesn't fully fit on the block,
        // continue feeding as many full SHA-256 blocks as possible.
        let data_full_blocks = (data.len() - data_bytes_used) / SHA256_BLOCK_SIZE;
        let data_words = data_full_blocks * SHA256_BLOCK_SIZE / WORD_SIZE;

        if data_full_blocks > 0 {
            let bytes = &data[data_bytes_used..data_bytes_used + data_words * WORD_SIZE];

            for chunk in bytes.chunks_exact(WORD_SIZE) {
                let mut buf = [0u8; WORD_SIZE];
                buf.copy_from_slice(chunk);
                let word = u32::from_be_bytes(buf);

                self.hash.din().write_value(word);
            }
        }

        // After consuming whole blocks, the remaining bytes will always fit within a single block.
        // Buffer the remainder, update the internal state, and save the hardware context.
        let data_bytes_used = data_bytes_used + data_full_blocks * SHA256_BLOCK_SIZE;
        instance.block[..data.len() - data_bytes_used].copy_from_slice(&data[data_bytes_used..]);
        instance.block_bytes_used = data.len() - data_bytes_used;
        instance.first_block = false;

        self.save_context(instance);
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        // Reset HASH state
        self.hash.cr().write(|w| w.set_init(true));
        while self.hash.cr().read().init() {}

        // Configure SHA-256
        self.configure_and_reset_context(instance.algorithm);

        // Restore the previously saved intermediate state for non-initial blocks.
        if !instance.first_block {
            self.restore_context(&instance);
        }

        for chunk in instance.block[..instance.block_bytes_used].chunks(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash.din().write_value(word);
        }

        let number_bytes_last_chunk = instance.block_bytes_used % WORD_SIZE;

        self.hash
            .str()
            .write(|w| w.set_nblw((number_bytes_last_chunk as u8) * 8));
        self.hash.str().write(|w| w.set_dcal(true));

        self.wait_busy();
        let mut hash_res_words: [u32; 8] = [0; 8];
        self.read_digest(&mut hash_res_words);

        let mut hash_result = [0u8; 32];
        for (i, w) in hash_res_words.iter().enumerate() {
            hash_result[i * WORD_SIZE..(i + 1) * WORD_SIZE].copy_from_slice(&w.to_be_bytes());
        }

        HashResult::Sha256(hash_result.into())
    }
}

impl Stm32wba55 {
    /// As documented in the HASH suspend/resume procedure.
    /// Used to suspend processing of the current message.
    /// https://www.st.com/resource/en/reference_manual/rm0493-multiprotocol-wireless-bluetooth-lowenergy-armbased-32bit-mcu-stmicroelectronics.pdf
    fn save_context(&mut self, instance: &mut HashState) {
        // BUSY must be 0
        while self.hash.sr().read().busy() {}

        // Save IMR + STR + CR registers
        instance.imr = self.hash.imr().read();
        instance.str = self.hash.str().read();
        instance.cr = self.hash.cr().read();

        // Save CSR registers (0..37 always; 38..53 only for HMAC)
        for i in 0..CSR_REGS_LEN {
            instance.csr[i] = self.hash.csr(i).read();
        }
    }

    /// As documented in the HASH suspend/resume procedure.
    /// Used to resume processing of an interrupted message.
    /// https://www.st.com/resource/en/reference_manual/rm0493-multiprotocol-wireless-bluetooth-lowenergy-armbased-32bit-mcu-stmicroelectronics.pdf
    fn restore_context(&mut self, ctx: &HashState) {
        self.hash.cr().write(|w| w.set_init(false));
        // 1. Restore IMR, STR, CR (with INIT=0)
        self.hash.imr().write_value(ctx.imr);
        self.hash.str().write_value(ctx.str);
        self.hash.cr().write(|w| {
            w.set_mode(false); // hash mode
            w.set_dmae(false);
            w.set_algo(3); // SHA2-256
            w.set_datatype(0)
        });

        // 2. Set INIT to reload STR/CR context into hardware
        self.hash.cr().modify(|w| w.set_init(true));
        while self.hash.cr().read().init() {}

        // 3. Restore CSR registers AFTER INIT has reinitialized the core
        for i in 0..CSR_REGS_LEN {
            self.hash.csr(i).write_value(ctx.csr[i])
        }
    }
    fn wait_busy(&mut self) {
        while self.hash.sr().read().busy() {}
        while !self.hash.sr().read().dcis() {}
    }

    fn configure_and_reset_context(&mut self, algo: HashAlgorithm) {
        match algo {
            HashAlgorithm::Sha256 => self.hash.cr().write(|w| {
                w.set_mode(false); // hash mode
                w.set_dmae(false);
                w.set_algo(3); // SHA2-256
                w.set_datatype(0);
                w.set_init(true)
            }),
        };
    }

    fn read_digest(&mut self, out: &mut [u32; 8]) {
        for i in 0..8 {
            out[i] = self.hash.hr(i).read();
        }
    }
}
