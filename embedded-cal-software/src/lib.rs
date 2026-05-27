//! Minimal stand-in for the libcrux based implementation and polyfills.
//!
//! Currently, this demonstrates how that layer would work on top of a hardware implementation that
//! only does the hard work of the SHA hashes and not the clerical buffering / padding.
#![no_std]

use embedded_cal::{Cal, plumbing::Plumbing};

mod aead;
mod hash;
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
impl<EC: ExtenderConfig> embedded_cal::Cal for Extender<EC> {}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) mod dummy_sha256;
}
