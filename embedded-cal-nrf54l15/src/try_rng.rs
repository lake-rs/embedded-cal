use crate::Nrf54l15Cal;
use nrf_pac::cracencore::vals::{ControlSoftrst, State};
const MAX_TRNG_RESTARTS: u32 = 3;

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

impl embedded_cal::TryRng for Nrf54l15Cal {
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
        let mut restarts = 0;

        while !dst.is_empty() {
            // Check the TRNG FSM state before waiting on the FIFO.
            //
            // The CRACEN TRNG can enter State::ERROR when its internal health
            // tests detect degraded entropy (NIST repetition/proportion test
            // failure, AIS31 noise alarm, or startup failure). In that state
            // the FIFO stops refilling and spinning on fifolevel() forever
            // produces a hang. The recovery sequence mirrors sx_trng_restart()
            // in sdk-nrf: pulse softrst CTEST→NORMAL then re-assert enable.
            //
            // Unlike transient startup/fill states (RESET, STARTUP, FILLFIFO),
            // ERROR indicates the noise source itself may be untrustworthy, so
            // we bound restarts: after MAX_TRNG_RESTARTS we return Err(HardwareFailure)
            // rather than looping forever or handing out potentially non-random bytes.
            let fsm = self.cracen_core.rngcontrol().status().read().state();
            if fsm == State::ERROR {
                restarts += 1;
                if restarts > MAX_TRNG_RESTARTS {
                    return Err(RngError::HardwareFailure);
                }

                // Pulse softrst to flush the conditioner and FIFO
                self.cracen_core
                    .rngcontrol()
                    .control()
                    .modify(|w| w.set_softrst(ControlSoftrst::CTEST));
                self.cracen_core
                    .rngcontrol()
                    .control()
                    .modify(|w| w.set_softrst(ControlSoftrst::NORMAL));
                self.cracen_core
                    .rngcontrol()
                    .control()
                    .modify(|w| w.set_enable(true));

                continue;
            }

            let level = loop {
                let l = self.cracen_core.rngcontrol().fifolevel().read();
                if l > 0 {
                    break l;
                }
                core::hint::spin_loop();
            };

            for _ in 0..level {
                if dst.is_empty() {
                    break;
                }

                // Always read fifo(0). The FIFO is a pop-on-read register; each read
                // advances the hardware read pointer.
                // Based on `cracen_get_random` from sdk-nrf C implementation
                let bytes = self.cracen_core.rngcontrol().fifo(0).read().to_le_bytes();
                let take = dst.len().min(4);
                dst[..take].copy_from_slice(&bytes[..take]);
                dst = &mut dst[take..];
            }
        }

        Ok(())
    }
}
