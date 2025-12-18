#![no_std]

use defmt_rtt as _;
use panic_probe as _;
use stm32wba::stm32wba55 as stm32wba55_pac;

pub struct Stm32wba55 {
    hash: stm32wba55_pac::HASH,
}

impl Stm32wba55 {
    pub fn new(hash: stm32wba55_pac::HASH, rcc: &stm32wba55_pac::RCC) -> Self {
        // Enable HASH clock
        rcc.rcc_ahb2enr().write(|w| w.hashen().set_bit());

        Self { hash }
    }
}

// #[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy, defmt::Format)]
pub enum HashAlgorithm {
    Sha256,
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }

    // FIXME: I am using the values from RFC 9054 here, is that correct?
    // https://www.rfc-editor.org/rfc/rfc9054.html#name-sha-2-hash-algorithms
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

#[derive(defmt::Format)]
pub struct HashState {
    algorithm: HashAlgorithm,
    csr: [u32; 54],
    str: u32,
    imr: u32,
    cr: u32,

    block: [u8; 68],
    block_bytes_used: usize,

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
            csr: [0; 54],
            str: 0,
            imr: 0,
            cr: 0,
            block: [0; 68],
            block_bytes_used: 0,
            first_block: true,
        }
    }

    fn update(&mut self, instance: &mut HashState, data: &[u8]) {
        // Reset HASH state
        self.hash.hash_cr().write(|w| w.init().set_bit());
        while self.hash.hash_cr().read().init().bit_is_set() {}

        self.configure_and_reset_context(instance.algorithm);

        if !instance.first_block {
            self.restore_context(&instance);
        }
        let block_size = if instance.first_block { 68 } else { 64 };
        if data.len() < (block_size - instance.block_bytes_used) {
            instance.block[instance.block_bytes_used..instance.block_bytes_used + data.len()]
                .copy_from_slice(data);
            instance.block_bytes_used += data.len();

            return;
        }
        let data_bytes_used = block_size - instance.block_bytes_used;

        instance.block[instance.block_bytes_used..block_size]
            .copy_from_slice(&data[..data_bytes_used]);

        for chunk in instance.block[..block_size].chunks_exact(4) {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash
                .hash_din()
                .write(|w| unsafe { w.datain().bits(word) });
        }

        let data_full_blocks = (data.len() - data_bytes_used) / 64;
        let data_words = data_full_blocks * 64 / 4;

        if data_full_blocks > 0 {
            let bytes = &data[data_bytes_used..data_bytes_used + data_words * 4];

            for chunk in bytes.chunks_exact(4) {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(chunk);
                let word = u32::from_be_bytes(buf);

                self.hash
                    .hash_din()
                    .write(|w| unsafe { w.datain().bits(word) });
            }
        }

        let data_bytes_used = data_bytes_used + data_full_blocks * 64;
        instance.block[..data.len() - data_bytes_used].copy_from_slice(&data[data_bytes_used..]);
        instance.block_bytes_used = data.len() - data_bytes_used;
        instance.first_block = false;

        self.save_context(instance);
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        // Reset HASH state
        self.hash.hash_cr().write(|w| w.init().set_bit());
        while self.hash.hash_cr().read().init().bit_is_set() {}

        // Configure SHA-256, 8-bit datatype
        self.configure_and_reset_context(instance.algorithm);

        if !instance.first_block {
            self.restore_context(&instance);
        }

        for chunk in instance.block[..instance.block_bytes_used].chunks(4) {
            let mut bytes = [0u8; 4];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash
                .hash_din()
                .write(|w| unsafe { w.datain().bits(word) });
        }

        let number_bytes_last_chunk = instance.block_bytes_used % 4;

        self.hash
            .hash_str()
            .write(|w| unsafe { w.nblw().bits(number_bytes_last_chunk as u8 * 8) });
        self.hash.hash_str().write(|w| w.dcal().set_bit());

        self.wait_busy();
        let mut hash_res_words: [u32; 8] = [0; 8];
        self.read_digest(&mut hash_res_words);

        let mut hash_result = [0u8; 32];
        for (i, w) in hash_res_words.iter().enumerate() {
            hash_result[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }

        HashResult::Sha256(hash_result.into())
    }
}

impl Stm32wba55 {
    fn save_context(&mut self, instance: &mut HashState) {
        // FIXME: BUSY must be 0
        instance.imr = self.hash.hash_imr().read().bits();
        instance.str = self.hash.hash_str().read().bits();
        instance.cr = self.hash.hash_cr().read().bits();

        // Save CSR registers (0..37 always; 38..53 only for HMAC)
        for i in 0..54 {
            instance.csr[i] = self.read_csr(i);
        }
    }

    fn restore_context(&mut self, ctx: &HashState) {
        self.hash.hash_cr().write(|w| w.init().clear_bit());
        // 1. Restore IMR, STR, CR (with INIT=0!)
        self.hash.hash_imr().write(|w| unsafe { w.bits(ctx.imr) });
        self.hash.hash_str().write(|w| unsafe { w.bits(ctx.str) });
        self.hash.hash_cr().write(|w| {
            w.mode().clear_bit(); // hash mode
            w.dmae().clear_bit();
            w.algo().b_0x3(); // SHA2-256
            w.datatype().b_0x0()
        });
        // Ensure INIT = 0 before we manually set it

        // 2. Set INIT to reload STR/CR context into hardware
        self.hash.hash_cr().modify(|_, w| w.init().set_bit());
        while self.hash.hash_cr().read().init().bit_is_set() {}

        // 3. Restore CSR registers AFTER INIT has reinitialized the core
        for i in 0..54 {
            self.write_csr(i, ctx.csr[i]);
        }
    }
    fn wait_busy(&mut self) {
        while self.hash.hash_sr().read().busy().bit_is_set() {}
        while self.hash.hash_sr().read().dcis().bit_is_clear() {}
    }

    fn configure_and_reset_context(&mut self, algo: HashAlgorithm) {
        match algo {
            HashAlgorithm::Sha256 => self.hash.hash_cr().write(|w| {
                w.mode().clear_bit(); // hash mode
                w.dmae().clear_bit();
                w.algo().b_0x3(); // SHA2-256
                w.datatype().b_0x0();
                w.init().set_bit()
            }),
        };
    }

    fn read_digest(&mut self, out: &mut [u32; 8]) {
        out[0] = self.hash.hash_hr0().read().bits();
        out[1] = self.hash.hash_hr1().read().bits();
        out[2] = self.hash.hash_hr2().read().bits();
        out[3] = self.hash.hash_hr3().read().bits();
        out[4] = self.hash.hash_hr4().read().bits();
        out[5] = self.hash.hash_hr5().read().bits();
        out[6] = self.hash.hash_hr6().read().bits();
        out[7] = self.hash.hash_hr7().read().bits();
    }

    fn read_csr(&mut self, idx: usize) -> u32 {
        match idx {
            0 => self.hash.hash_csr0().read().bits(),
            1 => self.hash.hash_csr1().read().bits(),
            2 => self.hash.hash_csr2().read().bits(),
            3 => self.hash.hash_csr3().read().bits(),
            4 => self.hash.hash_csr4().read().bits(),
            5 => self.hash.hash_csr5().read().bits(),
            6 => self.hash.hash_csr6().read().bits(),
            7 => self.hash.hash_csr7().read().bits(),
            8 => self.hash.hash_csr8().read().bits(),
            9 => self.hash.hash_csr9().read().bits(),
            10 => self.hash.hash_csr10().read().bits(),
            11 => self.hash.hash_csr11().read().bits(),
            12 => self.hash.hash_csr12().read().bits(),
            13 => self.hash.hash_csr13().read().bits(),
            14 => self.hash.hash_csr14().read().bits(),
            15 => self.hash.hash_csr15().read().bits(),
            16 => self.hash.hash_csr16().read().bits(),
            17 => self.hash.hash_csr17().read().bits(),
            18 => self.hash.hash_csr18().read().bits(),
            19 => self.hash.hash_csr19().read().bits(),
            20 => self.hash.hash_csr20().read().bits(),
            21 => self.hash.hash_csr21().read().bits(),
            22 => self.hash.hash_csr22().read().bits(),
            23 => self.hash.hash_csr23().read().bits(),
            24 => self.hash.hash_csr24().read().bits(),
            25 => self.hash.hash_csr25().read().bits(),
            26 => self.hash.hash_csr26().read().bits(),
            27 => self.hash.hash_csr27().read().bits(),
            28 => self.hash.hash_csr28().read().bits(),
            29 => self.hash.hash_csr29().read().bits(),
            30 => self.hash.hash_csr30().read().bits(),
            31 => self.hash.hash_csr31().read().bits(),
            32 => self.hash.hash_csr32().read().bits(),
            33 => self.hash.hash_csr33().read().bits(),
            34 => self.hash.hash_csr34().read().bits(),
            35 => self.hash.hash_csr35().read().bits(),
            36 => self.hash.hash_csr36().read().bits(),
            37 => self.hash.hash_csr37().read().bits(),
            38 => self.hash.hash_csr38().read().bits(),
            39 => self.hash.hash_csr39().read().bits(),
            40 => self.hash.hash_csr40().read().bits(),
            41 => self.hash.hash_csr41().read().bits(),
            42 => self.hash.hash_csr42().read().bits(),
            43 => self.hash.hash_csr43().read().bits(),
            44 => self.hash.hash_csr44().read().bits(),
            45 => self.hash.hash_csr45().read().bits(),
            46 => self.hash.hash_csr46().read().bits(),
            47 => self.hash.hash_csr47().read().bits(),
            48 => self.hash.hash_csr48().read().bits(),
            49 => self.hash.hash_csr49().read().bits(),
            50 => self.hash.hash_csr50().read().bits(),
            51 => self.hash.hash_csr51().read().bits(),
            52 => self.hash.hash_csr52().read().bits(),
            53 => self.hash.hash_csr53().read().bits(),
            _ => unreachable!(),
        }
    }

    fn write_csr(&mut self, idx: usize, value: u32) {
        match idx {
            0 => self.hash.hash_csr0().write(|w| unsafe { w.bits(value) }),
            1 => self.hash.hash_csr1().write(|w| unsafe { w.bits(value) }),
            2 => self.hash.hash_csr2().write(|w| unsafe { w.bits(value) }),
            3 => self.hash.hash_csr3().write(|w| unsafe { w.bits(value) }),
            4 => self.hash.hash_csr4().write(|w| unsafe { w.bits(value) }),
            5 => self.hash.hash_csr5().write(|w| unsafe { w.bits(value) }),
            6 => self.hash.hash_csr6().write(|w| unsafe { w.bits(value) }),
            7 => self.hash.hash_csr7().write(|w| unsafe { w.bits(value) }),
            8 => self.hash.hash_csr8().write(|w| unsafe { w.bits(value) }),
            9 => self.hash.hash_csr9().write(|w| unsafe { w.bits(value) }),
            10 => self.hash.hash_csr10().write(|w| unsafe { w.bits(value) }),
            11 => self.hash.hash_csr11().write(|w| unsafe { w.bits(value) }),
            12 => self.hash.hash_csr12().write(|w| unsafe { w.bits(value) }),
            13 => self.hash.hash_csr13().write(|w| unsafe { w.bits(value) }),
            14 => self.hash.hash_csr14().write(|w| unsafe { w.bits(value) }),
            15 => self.hash.hash_csr15().write(|w| unsafe { w.bits(value) }),
            16 => self.hash.hash_csr16().write(|w| unsafe { w.bits(value) }),
            17 => self.hash.hash_csr17().write(|w| unsafe { w.bits(value) }),
            18 => self.hash.hash_csr18().write(|w| unsafe { w.bits(value) }),
            19 => self.hash.hash_csr19().write(|w| unsafe { w.bits(value) }),
            20 => self.hash.hash_csr20().write(|w| unsafe { w.bits(value) }),
            21 => self.hash.hash_csr21().write(|w| unsafe { w.bits(value) }),
            22 => self.hash.hash_csr22().write(|w| unsafe { w.bits(value) }),
            23 => self.hash.hash_csr23().write(|w| unsafe { w.bits(value) }),
            24 => self.hash.hash_csr24().write(|w| unsafe { w.bits(value) }),
            25 => self.hash.hash_csr25().write(|w| unsafe { w.bits(value) }),
            26 => self.hash.hash_csr26().write(|w| unsafe { w.bits(value) }),
            27 => self.hash.hash_csr27().write(|w| unsafe { w.bits(value) }),
            28 => self.hash.hash_csr28().write(|w| unsafe { w.bits(value) }),
            29 => self.hash.hash_csr29().write(|w| unsafe { w.bits(value) }),
            30 => self.hash.hash_csr30().write(|w| unsafe { w.bits(value) }),
            31 => self.hash.hash_csr31().write(|w| unsafe { w.bits(value) }),
            32 => self.hash.hash_csr32().write(|w| unsafe { w.bits(value) }),
            33 => self.hash.hash_csr33().write(|w| unsafe { w.bits(value) }),
            34 => self.hash.hash_csr34().write(|w| unsafe { w.bits(value) }),
            35 => self.hash.hash_csr35().write(|w| unsafe { w.bits(value) }),
            36 => self.hash.hash_csr36().write(|w| unsafe { w.bits(value) }),
            37 => self.hash.hash_csr37().write(|w| unsafe { w.bits(value) }),
            38 => self.hash.hash_csr38().write(|w| unsafe { w.bits(value) }),
            39 => self.hash.hash_csr39().write(|w| unsafe { w.bits(value) }),
            40 => self.hash.hash_csr40().write(|w| unsafe { w.bits(value) }),
            41 => self.hash.hash_csr41().write(|w| unsafe { w.bits(value) }),
            42 => self.hash.hash_csr42().write(|w| unsafe { w.bits(value) }),
            43 => self.hash.hash_csr43().write(|w| unsafe { w.bits(value) }),
            44 => self.hash.hash_csr44().write(|w| unsafe { w.bits(value) }),
            45 => self.hash.hash_csr45().write(|w| unsafe { w.bits(value) }),
            46 => self.hash.hash_csr46().write(|w| unsafe { w.bits(value) }),
            47 => self.hash.hash_csr47().write(|w| unsafe { w.bits(value) }),
            48 => self.hash.hash_csr48().write(|w| unsafe { w.bits(value) }),
            49 => self.hash.hash_csr49().write(|w| unsafe { w.bits(value) }),
            50 => self.hash.hash_csr50().write(|w| unsafe { w.bits(value) }),
            51 => self.hash.hash_csr51().write(|w| unsafe { w.bits(value) }),
            52 => self.hash.hash_csr52().write(|w| unsafe { w.bits(value) }),
            53 => self.hash.hash_csr53().write(|w| unsafe { w.bits(value) }),
            _ => unreachable!(),
        };
    }
}
