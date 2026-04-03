#![no_std]

use stm32_metapac::{
    hash,
    rcc::{self, vals::Rngsel},
    rng::{
        self,
        vals::{Clkdiv, Htcfg, Nistc, RngConfig1, RngConfig2, RngConfig3},
    },
};
mod try_rng;

const WORD_SIZE: usize = 4;
const CSR_REGS_LEN: usize = 54;

pub struct Stm32wba55Cal {
    hash: hash::Hash,
    rcc: rcc::Rcc,
    rng: rng::Rng,
}

impl embedded_cal::Cal for Stm32wba55Cal {}

impl Stm32wba55Cal {
    pub fn new(hash: hash::Hash, rcc: rcc::Rcc, rng: rng::Rng) -> Self {
        // Select HSI as the RNG kernel clock source (default is LSE which may not be running)
        rcc.ccipr2().modify(|w| w.set_rngsel(Rngsel::HSI));

        // Enable HASH and RNG clocks
        rcc.ahb2enr().modify(|w| {
            w.set_hashen(true);
            w.set_rngen(true);
        });

        let mut cal = Self { hash, rcc, rng };
        cal.init_rng().expect("RNG init failed");
        cal
    }

    /// Initialize the RNG peripheral using the rng_v3 conditioning sequence.
    ///
    /// Must be called once after enabling the RNG clock, and again on seed error recovery.
    /// Uses NIST config A (certifiable). The HTCR magic number must precede any HTCR write
    /// per the RM0493 requirement.
    fn init_rng(&mut self) -> Result<(), try_rng::RngError> {
        // Enter conditioning reset with NIST config A settings
        self.rng.cr().write(|w| {
            w.set_condrst(true);
            w.set_nistc(Nistc::CUSTOM);
            w.set_rng_config1(RngConfig1::CONFIG_A);
            w.set_clkdiv(Clkdiv::NO_DIV);
            w.set_rng_config2(RngConfig2::CONFIG_A_B);
            w.set_rng_config3(RngConfig3::CONFIG_A);
            w.set_ced(true); // disable clock error detection during conditioning
            w.set_ie(false);
            w.set_rngen(true);
        });

        // Wait for conditioning reset to take effect
        wait_for(|| self.rng.cr().read().condrst())?;

        // Write health test config: magic number must immediately precede the actual value
        self.rng.htcr().write(|w| w.set_htcfg(Htcfg::MAGIC));
        self.rng.htcr().write(|w| w.set_htcfg(Htcfg::RECOMMENDED));

        // Clear conditioning reset and re-enable clock error detection
        self.rng.cr().modify(|w| {
            w.set_condrst(false);
            w.set_ced(false); // re-enable clock error detection (was disabled during conditioning)
        });

        // Wait for conditioning reset to deassert (RM0493 requires waiting for both assert and deassert)
        wait_for(|| !self.rng.cr().read().condrst())?;

        // Clear any latched seed error from the reset
        self.rng.sr().modify(|w| w.set_seis(false));

        // Discard the first output word (required after every reset per RM0493).
        // Also unblock on seis so a seed error during conditioning doesn't hang forever.
        wait_for(|| {
            let sr = self.rng.sr().read();
            sr.drdy() || sr.seis()
        })?;
        if self.rng.sr().read().seis() {
            return Err(try_rng::RngError::HardwareFailure);
        }
        let _ = self.rng.dr().read();

        Ok(())
    }
}

fn wait_for(mut condition: impl FnMut() -> bool) -> Result<(), try_rng::RngError> {
    for _ in 0..1000 {
        if condition() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(try_rng::RngError::HardwareFailure)
}

impl Drop for Stm32wba55Cal {
    fn drop(&mut self) {
        // Disable HASH clock
        self.rcc.ahb2enr().modify(|w| w.set_hashen(false));
        self.rng.cr().modify(|w| w.set_rngen(false));
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
}

pub struct HashState {
    _variant: embedded_cal::plumbing::hash::Sha2ShortVariant,
    context: Option<Context>,
}

struct Context {
    /// HASH context swap registers (HASH_CSR0 - HASH_CSR53)
    csr: [u32; CSR_REGS_LEN],
    /// HASH start register (HASH_STR)
    str: hash::regs::Str,
    /// HASH interrupt enable register (HASH_IMR)
    imr: hash::regs::Imr,
}

impl embedded_cal::HashProvider for Stm32wba55Cal {
    type Algorithm = embedded_cal::NoHashAlgorithms;
    type HashState = embedded_cal::NoHashAlgorithms;
    type HashResult = embedded_cal::NoHashAlgorithms;

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

impl embedded_cal::plumbing::Plumbing for Stm32wba55Cal {}

impl embedded_cal::plumbing::hash::Hash for Stm32wba55Cal {}

impl embedded_cal::plumbing::hash::Sha2Short for Stm32wba55Cal {
    const SUPPORTED: bool = true;
    const SEND_PADDING: bool = false;
    const FIRST_CHUNK_SIZE: usize = 68;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        Self::State {
            _variant: variant,
            context: None,
        }
    }

    fn update(&mut self, instance: &mut HashState, data: &[u8]) {
        // Reinitialize the HASH peripheral before processing new input
        self.hash.cr().write(|w| w.set_init(true));
        while self.hash.cr().read().init() {}
        self.configure_and_reset_context(HashAlgorithm::Sha256);

        // Restore the previously saved intermediate state for non-initial blocks.
        if let Some(context) = &instance.context {
            self.restore_context(context);
        }

        // Hardware can only pause hashing after exactly NBWE (Number of words expected) words have been written.
        // For SHA-256 this corresponds to 17 words for the first block, and 16 words for all subsequent blocks.
        // Equivalent value available at: self.hash.sr().read().nbwe().bits()
        for chunk in data.chunks_exact(WORD_SIZE) {
            let mut bytes = [0u8; WORD_SIZE];
            bytes.copy_from_slice(chunk);
            let word = u32::from_be_bytes(bytes);

            self.hash.din().write_value(word);
        }

        self.save_context(instance);
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        // Reset HASH state
        self.hash.cr().write(|w| w.set_init(true));
        while self.hash.cr().read().init() {}

        // Configure SHA-256
        self.configure_and_reset_context(HashAlgorithm::Sha256);

        // Restore the previously saved intermediate state for non-initial blocks.
        if let Some(context) = &instance.context {
            self.restore_context(context);
        }

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

impl Stm32wba55Cal {
    /// As documented in the HASH suspend/resume procedure.
    /// Used to suspend processing of the current message.
    /// https://www.st.com/resource/en/reference_manual/rm0493-multiprotocol-wireless-bluetooth-lowenergy-armbased-32bit-mcu-stmicroelectronics.pdf
    fn save_context(&mut self, instance: &mut HashState) {
        // BUSY must be 0
        while self.hash.sr().read().busy() {}

        // Save IMR + STR registers
        let imr = self.hash.imr().read();
        let str = self.hash.str().read();

        // Save CSR registers (0..37 always; 38..53 only for HMAC)
        let mut csr = [0u32; CSR_REGS_LEN];
        for i in 0..CSR_REGS_LEN {
            csr[i] = self.hash.csr(i).read();
        }
        instance.context = Some(Context { csr, str, imr });
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
