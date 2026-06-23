// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::RustcryptoCalExtender;
use embedded_cal::Cal;

/// An implementation based on `getrandom`.
///
/// Unlike lakers, we just require that getrandom is provided; Ariel OS's random module shows that
/// this can be done also on embedded platforms.
// FIXME: We should probably have some fast CSPRNG in self that is just seeded from getrandom.
impl<Base: Cal> rand_core::TryCryptoRng for RustcryptoCalExtender<Base> {}

impl<Base: Cal> rand_core::TryRng for RustcryptoCalExtender<Base> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(getrandom::u32().expect("platform RNG failure"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(getrandom::u64().expect("platform RNG failure"))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("platform RNG failure");
        Ok(())
    }
}
