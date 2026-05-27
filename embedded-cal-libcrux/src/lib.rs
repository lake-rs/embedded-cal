//! libcrux-sha2 backed SHA-256, plus plumbing to extend any hardware-backed [`Cal`] with it.
#![no_std]

use embedded_cal::{Cal, plumbing::Plumbing};
use libcrux_sha2::Digest;

mod aead;
mod empty_impls;
mod hash;

pub trait ExtenderConfig {
    // Currently we could also just have a Base in the generic and do not use Plumbing, but we
    // *will* use it in the future, and that will need more options, so this is reusing the design
    // of -software-demo even though there is no immediate benefit.

    type Base: Cal + Plumbing;
}

pub struct Extender<EC: ExtenderConfig>(EC::Base);

impl<EC: ExtenderConfig> Extender<EC> {
    pub fn new(base: EC::Base) -> Self {
        Self(base)
    }
}

impl<EC: ExtenderConfig> Cal for Extender<EC> {}
