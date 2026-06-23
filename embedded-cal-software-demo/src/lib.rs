// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Minimal stand-in for the libcrux based implementation and polyfills.
//!
//! Currently, this demonstrates how that layer would work on top of a hardware implementation that
//! only does the hard work of the SHA hashes and not the clerical buffering / padding.
#![no_std]

use embedded_cal::{Cal, accessor::*, plumbing::Plumbing};

mod hash;
mod hkdf;
mod hmac;
mod rng;

pub trait ExtenderConfig {
    const IMPLEMENT_SHA2SHORT: bool;

    type Base: Cal + Plumbing;
}

impl<EC: ExtenderConfig> Extender<EC> {
    pub fn new(base: EC::Base) -> Self {
        Self(base)
    }
}

pub struct Extender<EC: ExtenderConfig>(EC::Base);

// All the required trait impls come from the modules.
impl<EC: ExtenderConfig> embedded_cal::Cal for Extender<EC> {
    type DhProvider = DhProviderOf<EC::Base>;
    type AeadProvider = AeadProviderOf<EC::Base>;
    type HashProvider = Self;
    type HmacProvider = Self;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.0.dh()
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self.0.aead()
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) mod dummy_sha256;
}
