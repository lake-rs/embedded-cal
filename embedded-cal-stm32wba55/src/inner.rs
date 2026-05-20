use embedded_cal_core::plumbing::hash::SHA2SHORT_BLOCK_SIZE;
use stm32_metapac::{hash, rcc};

const WORD_SIZE: usize = 4;
const CSR_REGS_LEN: usize = 54;
/// Block size for SHA-256 (and the HMAC message phase).
const HMAC_MAX_BLOCK_SIZE: usize = 68;
const SHA256_OUT_BYTES: usize = 32;

pub struct Stm32wba55CalInner {
    hash: hash::Hash,
}

pub struct HashState {
    pub(crate) _variant: embedded_cal_core::plumbing::hash::Sha2ShortVariant,
    pub(crate) context: Option<Context>,
}

pub(crate) struct Context {
    /// HASH context swap registers (HASH_CSR0 - HASH_CSR53)
    pub(crate) csr: [u32; CSR_REGS_LEN],
    /// HASH start register (HASH_STR)
    pub(crate) str: hash::regs::Str,
    /// HASH interrupt enable register (HASH_IMR)
    pub(crate) imr: hash::regs::Imr,
}

pub(crate) enum HashResult {
    Sha256([u8; 32]),
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub(crate) enum HashAlgorithm {
    Sha256,
}

/// HMAC algorithm identifier for the STM32WBA55 hardware accelerator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HmacAlgorithm {
    HmacSha256,
}

impl embedded_cal_core::HmacAlgorithm for HmacAlgorithm {
    fn len(&self) -> usize {
        match self {
            HmacAlgorithm::HmacSha256 => 32,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            5 => Some(HmacAlgorithm::HmacSha256),
            _ => None,
        }
    }
}

/// State for an in-progress HMAC-SHA256 operation.
pub struct HmacState {
    pub(crate) context: Option<Context>,
    pub(crate) buf: [u8; HMAC_MAX_BLOCK_SIZE],
    pub(crate) buf_len: usize,
    pub(crate) key_block: [u8; SHA2SHORT_BLOCK_SIZE],
}

pub struct HmacResult(pub(crate) [u8; 32]);

impl AsRef<[u8]> for HmacResult {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Stm32wba55CalInner {
    pub(crate) fn new_inner(hash: hash::Hash, rcc: &rcc::Rcc) -> Self {
        // Enable HASH clock
        rcc.ahb2enr().modify(|w| w.set_hashen(true));
        Self { hash }
    }
}

impl embedded_cal_core::Cal for Stm32wba55CalInner {}

impl embedded_cal_core::HashProvider for Stm32wba55CalInner {
    type Algorithm = embedded_cal_core::NoHashAlgorithms;
    type HashState = embedded_cal_core::NoHashAlgorithms;
    type HashResult = embedded_cal_core::NoHashAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::HashState, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {}
    }
}

impl embedded_cal_core::HmacProvider for Stm32wba55CalInner {
    type Algorithm = HmacAlgorithm;
    type HmacState = HmacState;
    type HmacResult = HmacResult;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
        match algorithm {
            HmacAlgorithm::HmacSha256 => {
                // Normalise key: zero-pad short keys; hash long keys per RFC 2104.
                let mut key_block = [0u8; SHA2SHORT_BLOCK_SIZE];
                if key.len() > SHA2SHORT_BLOCK_SIZE {
                    let hashed = self.sha256_of(key);
                    key_block[..SHA256_OUT_BYTES].copy_from_slice(&hashed);
                } else {
                    key_block[..key.len()].copy_from_slice(key);
                }

                // Initialise the HASH peripheral in HMAC-SHA256 mode.
                self.hash.cr().write(|w| {
                    w.set_mode(true); // HMAC
                    w.set_dmae(false);
                    w.set_algo(3); // SHA-256
                    w.set_datatype(0); // 32-bit words, no byte-swap
                    w.set_lkey(false); // always false, because we save the key as sha-256
                    w.set_init(true);
                });
                while self.hash.cr().read().init() {}

                // Feed the inner key (64 bytes = 16 full 32-bit words).
                for chunk in key_block.chunks_exact(WORD_SIZE) {
                    let mut bytes = [0u8; WORD_SIZE];
                    bytes.copy_from_slice(chunk);
                    self.hash.din().write_value(u32::from_be_bytes(bytes));
                }
                // NBLW = 0: all 16 words are full (no partial last word).
                self.hash.str().write(|w| w.set_nblw(0));
                self.hash.str().write(|w| w.set_dcal(true));

                // Wait until the hardware has processed the key and is ready for message data.
                while !self.hash.sr().read().dinis() {}

                HmacState {
                    context: Some(self.read_context()),
                    buf: [0; HMAC_MAX_BLOCK_SIZE],
                    buf_len: 0,
                    key_block,
                }
            }
        }
    }

    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]) {
        let mut remaining = data;
        let mut wrote_blocks = false;

        while !remaining.is_empty() {
            let hmac_block_size = self.hash.sr().read().nbwe() as usize * WORD_SIZE;
            let space = hmac_block_size - state.buf_len;
            let take = remaining.len().min(space);
            state.buf[state.buf_len..state.buf_len + take].copy_from_slice(&remaining[..take]);
            state.buf_len += take;
            remaining = &remaining[take..];

            if state.buf_len == hmac_block_size {
                if !wrote_blocks {
                    //  Restore hardware context before the first write of this call.
                    if let Some(ctx) = state.context.take() {
                        self.restore_context_hmac(&ctx);
                    }
                    wrote_blocks = true;
                }
                // Write a complete 64-byte block (16 words) to the hardware.
                for chunk in state.buf[..state.buf_len].chunks_exact(WORD_SIZE) {
                    let mut bytes = [0u8; WORD_SIZE];
                    bytes.copy_from_slice(chunk);
                    self.hash.din().write_value(u32::from_be_bytes(bytes));
                }
                state.buf_len = 0;
            }
        }

        if wrote_blocks {
            // Capture the updated hardware context for the next call.
            state.context = Some(self.read_context());
        }
    }

    fn finalize(&mut self, mut state: Self::HmacState) -> Self::HmacResult {
        // Restore hardware to the last saved context.
        if let Some(ctx) = state.context.take() {
            self.restore_context_hmac(&ctx);
        }

        // Write the remaining buffered bytes (the last, possibly partial, message block).
        let buf_len = state.buf_len;
        for chunk in state.buf[..buf_len].chunks(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes[..chunk.len()].copy_from_slice(chunk);
            self.hash.din().write_value(u32::from_be_bytes(bytes));
        }
        // NBLW: number of valid bits in the last word (0 = full 32-bit word).
        let nblw = (buf_len % WORD_SIZE) as u8 * 8;
        self.hash.str().write(|w| w.set_nblw(nblw));
        self.hash.str().write(|w| w.set_dcal(true));
        while !self.hash.sr().read().dinis() {}

        // Feed the outer key (same 64-byte block as the inner key).
        for chunk in state.key_block.chunks_exact(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes.copy_from_slice(chunk);
            self.hash.din().write_value(u32::from_be_bytes(bytes));
        }
        // NBLW = 0: all 16 words of the outer key are full.
        self.hash.str().write(|w| w.set_nblw(0));
        self.hash.str().write(|w| w.set_dcal(true));

        // Wait for DCIS: HMAC digest is ready.
        self.wait_busy();

        let mut words = [0u32; 8];
        self.read_digest(&mut words);

        let mut result = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            result[i * WORD_SIZE..(i + 1) * WORD_SIZE].copy_from_slice(&w.to_be_bytes());
        }
        HmacResult(result)
    }
}

impl embedded_cal_core::plumbing::Plumbing for Stm32wba55CalInner {}

impl embedded_cal_core::plumbing::hash::Hash for Stm32wba55CalInner {}

impl embedded_cal_core::plumbing::hash::Sha2Short for Stm32wba55CalInner {
    const SUPPORTED: bool = true;
    const SEND_PADDING: bool = false;
    const FIRST_CHUNK_SIZE: usize = 68;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(
        &mut self,
        variant: embedded_cal_core::plumbing::hash::Sha2ShortVariant,
    ) -> Self::State {
        Self::State {
            _variant: variant,
            context: None,
        }
    }

    fn update(&mut self, instance: &mut HashState, data: &[u8]) {
        debug_assert_eq!(
            data.len(),
            self.hash.sr().read().nbwe() as usize * WORD_SIZE,
            "data length must match NBWE words expected by the hardware"
        );

        self.reinit_and_restore(&instance.context);

        // Hardware can only pause hashing after exactly NBWE (Number of words expected) words have been written.
        // For SHA-256 this corresponds to 17 words for the first block, and 16 words for all subsequent blocks.
        for chunk in data.chunks_exact(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes.copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash.din().write_value(word);
        }

        self.save_context(instance);
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        self.reinit_and_restore(&instance.context);

        for chunk in last_chunk.chunks(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash.din().write_value(word);
        }

        let number_bytes_last_chunk = last_chunk.len() % WORD_SIZE;

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

        target.copy_from_slice(&hash_result[..32]);
    }
}

impl Stm32wba55CalInner {
    /// Reinitializes the HASH peripheral, configures it for SHA-256, and restores
    /// any previously saved intermediate context.
    fn reinit_and_restore(&mut self, context: &Option<Context>) {
        self.hash.cr().write(|w| w.set_init(true));
        while self.hash.cr().read().init() {}
        self.configure_and_reset_context(HashAlgorithm::Sha256);

        if let Some(ctx) = context {
            self.restore_context(ctx);
        }
    }

    /// As documented in the HASH suspend/resume procedure.
    /// Used to suspend processing of the current message.
    /// https://www.st.com/resource/en/reference_manual/rm0493-multiprotocol-wireless-bluetooth-lowenergy-armbased-32bit-mcu-stmicroelectronics.pdf
    fn save_context(&mut self, instance: &mut HashState) {
        instance.context = Some(self.read_context());
    }

    /// Reads and returns the current HASH hardware context (IMR, STR, and all CSRs).
    ///
    /// Waits for BUSY = 0 before reading, as required by the suspend/resume procedure.
    fn read_context(&mut self) -> Context {
        // BUSY must be 0
        while self.hash.sr().read().busy() {}

        let imr = self.hash.imr().read();
        let str = self.hash.str().read();

        // Save CSR registers (0..37 always; 38..53 also needed for HMAC)
        let mut csr = [0u32; CSR_REGS_LEN];
        for (i, slot) in csr.iter_mut().enumerate() {
            *slot = self.hash.csr(i).read();
        }
        Context { csr, str, imr }
    }

    /// As documented in the HASH suspend/resume procedure.
    /// Used to resume processing of an interrupted message.
    /// https://www.st.com/resource/en/reference_manual/rm0493-multiprotocol-wireless-bluetooth-lowenergy-armbased-32bit-mcu-stmicroelectronics.pdf
    fn restore_context(&mut self, ctx: &Context) {
        self.hash.cr().write(|w| w.set_init(false));
        // Restore IMR, STR (with INIT=0)
        self.hash.imr().write_value(ctx.imr);
        self.hash.str().write_value(ctx.str);
        self.hash.cr().write(|w| {
            w.set_mode(false); // hash mode
            w.set_dmae(false);
            w.set_algo(3); // SHA2-256
            w.set_datatype(0)
        });

        // Set INIT to reload STR/CR context into hardware
        self.hash.cr().modify(|w| w.set_init(true));
        while self.hash.cr().read().init() {}

        // Restore CSR registers AFTER INIT has reinitialized the core
        for i in 0..CSR_REGS_LEN {
            self.hash.csr(i).write_value(ctx.csr[i])
        }
    }

    /// Resume an interrupted HMAC-SHA256 operation.
    ///
    /// Identical to [`restore_context`] but sets `MODE = 1` (HMAC) and `LKEY = 0`.
    fn restore_context_hmac(&mut self, ctx: &Context) {
        self.hash.cr().write(|w| w.set_init(false));
        self.hash.imr().write_value(ctx.imr);
        self.hash.str().write_value(ctx.str);
        self.hash.cr().write(|w| {
            w.set_mode(true); // HMAC mode
            w.set_dmae(false);
            w.set_algo(3); // SHA2-256
            w.set_datatype(0);
            w.set_lkey(false);
        });
        self.hash.cr().modify(|w| w.set_init(true));
        while self.hash.cr().read().init() {}
        for i in 0..CSR_REGS_LEN {
            self.hash.csr(i).write_value(ctx.csr[i]);
        }
    }

    /// Compute SHA-256 of `data` using the hardware accelerator.
    ///
    /// Used internally to hash HMAC keys that are longer than 64 bytes (RFC 2104).
    fn sha256_of(&mut self, data: &[u8]) -> [u8; 32] {
        use embedded_cal_core::plumbing::hash::{
            SHA2SHORT_BLOCK_SIZE, Sha2Short, Sha2ShortVariant,
        };

        let mut instance = <Self as Sha2Short>::init(self, Sha2ShortVariant::Sha256);
        let mut remaining = data;
        let mut first = true;

        loop {
            let chunk_size = if first {
                <Self as Sha2Short>::FIRST_CHUNK_SIZE
            } else {
                SHA2SHORT_BLOCK_SIZE
            };
            if remaining.len() <= chunk_size {
                break;
            }
            <Self as Sha2Short>::update(self, &mut instance, &remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            first = false;
        }

        let mut output = [0u8; 32];
        <Self as Sha2Short>::finalize(self, instance, remaining, &mut output);
        output
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
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.hash.hr(i).read();
        }
    }
}
