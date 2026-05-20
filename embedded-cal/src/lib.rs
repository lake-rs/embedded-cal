#![no_std]

pub use embedded_cal_core::*;

#[cfg(feature = "nrf54l15")]
pub use embedded_cal_nrf54l15::Nrf54l15Cal;

#[cfg(feature = "stm32wba55cg")]
pub use embedded_cal_stm32wba55::Stm32wba55Cal;
