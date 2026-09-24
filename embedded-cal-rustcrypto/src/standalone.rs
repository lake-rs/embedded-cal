// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::empty;

use super::*;

/// Type alias for the output of [`Standalone::standalone()`]
pub type Standalone = RustcryptoCalExtender<embedded_cal_rand::WithSysRng<empty::EmptyCal>>;

impl Standalone {
    /// Creates a software-only cal, whose RNG functionality is backed by the system as chosen by
    /// [`rand::make_rng()`](https://docs.rs/rand/latest/rand/fn.make_rng.html).
    pub fn standalone() -> Self {
        Self::new_extending(embedded_cal_rand::WithSysRng::new_from_sys(empty::EmptyCal))
    }
}

impl Default for Standalone {
    fn default() -> Self {
        Self::standalone()
    }
}
