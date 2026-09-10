// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! libcrux-sha2 backed SHA-256, SHA-3, and AES-CCM/GCM, plus plumbing to extend any hardware-backed [`Cal`] with it.
//!
//! ## Secret Independence Checking
//!
//! The embedded-cal libcrux provider provides a libcrux-iot backed SHA-3 implementation that performs secret
//! independence checking via the [libcrux-secrets][ls] crate. The secret independence checking of libcrux-secrets
//! is performed via the Rust type system. By enabling the cargo feature `check-secret-independence` of the
//! embedded-cal-libcrux crate, you can re-prove that the SHA-3 is indeed secret
//! independent on the source code level.
//!
//! <div class="warning">
//!
//! The `check-secret-independence` feature is not intended to be enabled unconditionally.
//! You should only enable it locally/in CI.
//!
//! </div>
//!
//! [ls]: https://docs.rs/libcrux-secrets/latest/libcrux_secrets/
#![no_std]

use embedded_cal::{Cal, accessor::*, plumbing::Plumbing};
use libcrux_sha2::Digest;

mod aead;
mod hash;

pub use hash::{HashAlgorithm, HashResult, HashState};

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

impl<EC: ExtenderConfig> Cal for Extender<EC> {
    type DhProvider = DhProviderOf<EC::Base>;
    type AeadProvider = Self;
    type HashProvider = Self;
    // FIXME: This should just be provided as well.
    type HmacProvider = HmacProviderOf<EC::Base>;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.0.dh()
    }
    fn aead(&mut self) -> &mut Self::AeadProvider {
        self
    }
    fn hash(&mut self) -> &mut Self::HashProvider {
        self
    }
    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self.0.hmac()
    }
}
