// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Implement the rand Rng traits by delegating to the base

use embedded_cal::{
    Cal,
    plumbing::{
        Plumbing,
        ec::Ec,
        hash::{Hash, Sha2Short},
    },
};

use crate::{Extender, ExtenderConfig};

/// An adapter for combining a [`Cal`] and an Rng.
///
/// This implements both the [`Cal`] trait and the [`rand_core`] traits,
/// depending on what the underlying generic types implement,
/// delegating to their implementations.
pub struct WithRng<C, R> {
    pub cal: C,
    pub rng: R,
}

impl<C, R> WithRng<C, R> {
    pub fn new(cal: C, rng: R) -> Self {
        WithRng { cal, rng }
    }
}

impl<C: Cal, R> Cal for WithRng<C, R> {
    type DhProvider = C::DhProvider;

    type AeadProvider = C::AeadProvider;

    type HashProvider = C::HashProvider;

    type HmacProvider = C::HmacProvider;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.cal.dh()
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self.cal.aead()
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self.cal.hash()
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self.cal.hmac()
    }
}

impl<C: Sha2Short, R> Sha2Short for WithRng<C, R> {
    const SUPPORTED: bool = C::SUPPORTED;

    const SEND_PADDING: bool = C::SEND_PADDING;

    const FIRST_CHUNK_SIZE: usize = C::FIRST_CHUNK_SIZE;

    const UPDATE_MULTICHUNK: bool = C::UPDATE_MULTICHUNK;

    type State = C::State;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        self.cal.init(variant)
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        self.cal.update(instance, data)
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        self.cal.finalize(instance, last_chunk, target)
    }
}

impl<C: Hash, R> Hash for WithRng<C, R> {}

impl<C: Ec, R> Ec for WithRng<C, R> {
    const MAX_SCALAR_LENGTH: usize = C::MAX_SCALAR_LENGTH;

    type PrimitivesP256 = C::PrimitivesP256;

    type PrimitivesX25519 = C::PrimitivesX25519;

    type PrimitivesX448 = C::PrimitivesX448;

    fn p256(&mut self) -> &mut Self::PrimitivesP256 {
        self.cal.p256()
    }

    fn x25519(&mut self) -> &mut Self::PrimitivesX25519 {
        self.cal.x25519()
    }

    fn x448(&mut self) -> &mut Self::PrimitivesX448 {
        self.cal.x448()
    }
}

impl<C: Plumbing, R> Plumbing for WithRng<C, R> {}

impl<C, R: rand_core::TryRng> rand_core::TryRng for WithRng<C, R> {
    type Error = R::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.rng.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.rng.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.try_fill_bytes(dst)
    }
}

impl<C, R: rand_core::CryptoRng> rand_core::TryCryptoRng for WithRng<C, R> {}

impl<EC> rand_core::TryCryptoRng for Extender<EC> where
    EC: ExtenderConfig<Base: rand_core::TryCryptoRng>
{
}

impl<EC> rand_core::TryRng for Extender<EC>
where
    EC: ExtenderConfig<Base: rand_core::TryRng>,
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
