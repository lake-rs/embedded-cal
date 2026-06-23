// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::{Extender, ExtenderConfig};

impl<EC: ExtenderConfig> rand_core::TryCryptoRng for Extender<EC> where
    EC::Base: rand_core::TryCryptoRng
{
}

impl<EC: ExtenderConfig> rand_core::TryRng for Extender<EC>
where
    EC::Base: rand_core::TryRng,
{
    type Error = <EC::Base as rand_core::TryRng>::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}
