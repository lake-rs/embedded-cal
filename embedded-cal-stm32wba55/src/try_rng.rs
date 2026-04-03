use crate::Stm32wba55Cal;
const MAX_SEED_RETRIES: u32 = 3;

/// Error returned by [`RngProvider::try_fill_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// The hardware noise source failed its internal health test too many times.
    ///
    /// This indicates the entropy source may be untrustworthy (degraded oscillator,
    /// power instability, or a silicon fault).
    HardwareFailure,
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RngError::HardwareFailure => write!(f, "hardware noise source failed health test"),
        }
    }
}

impl core::error::Error for RngError {}

impl embedded_cal::TryRng for Stm32wba55Cal {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let mut dst = dst;
        let mut seed_errors: u32 = 0;

        while !dst.is_empty() {
            let sr = self.rng.sr().read();

            if sr.seis() {
                // Seed error: the hardware noise source failed its internal health
                // test. Clear the flag and re-run the full NIST conditioning sequence.
                //
                // Unlike a clock error (ceis), which self-recovers once the clock
                // stabilizes, seis indicates the entropy source itself may be
                // degraded (bad oscillator, power instability, temperature extreme,
                // or a silicon fault). Re-initializing in that case just loops back
                // to the same failure, so we bound retries: after MAX_SEED_RETRIES
                // consecutive seed errors we give up and return Err(()) rather than
                // spinning forever or handing out potentially non-random bytes.
                seed_errors += 1;
                if seed_errors > MAX_SEED_RETRIES {
                    return Err(RngError::HardwareFailure);
                }
                self.rng.sr().modify(|w| w.set_seis(false));
                self.init_rng()?;
                continue;
            }

            if sr.ceis() {
                // Clock error: clear flag, hardware recovers automatically
                self.rng.sr().modify(|w| w.set_ceis(false));
                continue;
            }

            if sr.drdy() {
                let bytes = self.rng.dr().read().to_le_bytes();
                let take = dst.len().min(crate::WORD_SIZE);
                dst[..take].copy_from_slice(&bytes[..take]);
                dst = &mut dst[take..];
                seed_errors = 0;
            } else {
                core::hint::spin_loop();
            }
        }

        Ok(())
    }
}
