//! Module that provides an [`embedded-cal::Cal`] instance like Ariel OS should on the long term.

#[allow(unused, reason = "just the non-empty peripherals need this")]
use ariel_os::hal::peripherals;

cfg_select! {
    feature = "embedded-cal-stm32wba55" => {ariel_os::hal::define_peripherals!(Peripherals {
        hash: HASH,
    });}
    _ => {ariel_os::hal::define_peripherals!(Peripherals {});}
}

/// Instanciates a Cal instance.
///
/// The current implementation is the most trivial possible, and just returns the software
/// implementation. Once this should support hardware, it'll grow an autostartable peripherals
/// argument (that'll vanish again once moved into Ariel OS itself).
pub fn cal(peripherals: Peripherals) -> impl embedded_cal::Cal {
    cfg_select! {
        feature = "embedded-cal-stm32wba55" => {
            use embassy_stm32::{bind_interrupts, hash, peripherals};

            bind_interrupts!(struct Irqs {
                HASH => hash::InterruptHandler<peripherals::HASH>;
            });

            // We're initializing the peripheral so that clocks are set up. On low-power setups it
            // also sets up the right power level counters.
            //
            // Using the embassy_stm32::hash ISRs (even though we don't need any because of
            // busy-polling) should not do any harm for initial tests.
            //
            // On the long run, we might just want to roll with Embassy (see
            // <https://github.com/lake-rs/embedded-cal/issues/35>).
            let hash = hash::Hash::new_blocking(peripherals.hash, Irqs);
            // FIXME: Probably dropping is just as good, but maybe the low-power parts that would
            // be decremented in Drop are just not implemented on it?
            core::mem::forget(hash);
            // SAFETY: We just dropped an owned Embassy hash peripheral that is based on this
            // underlying one, so we're exclusive users.
            let hash = unsafe { stm32_metapac::HASH };
            // When we set up blocking(), the clock got turned on.
            embedded_cal_stm32wba55::Stm32wba55Cal::new_with_hash_clock_enabled(hash)
        },
        _ => {
            let _ = peripherals;
            embedded_cal_rustcrypto::RustcryptoCal
        }
    }
}
