// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
use embedded_cal::empty::EmptyCal;

pub struct StandaloneConfig;

impl super::ExtenderConfig for StandaloneConfig {
    type Base = embedded_cal_rand::WithSysRng<EmptyCal>;
}

/// Type alias for the output of [`Standalone::standalone()`]
pub type Standalone = super::Extender<StandaloneConfig>;

impl Standalone {
    /// Creates a software-only cal, whose RNG functionality is backed by the system as chosen by
    /// [`rand::make_rng()`](https://docs.rs/rand/latest/rand/fn.make_rng.html).
    pub fn standalone() -> Self {
        Self::new(embedded_cal_rand::WithSysRng::new_from_sys(EmptyCal))
    }
}
