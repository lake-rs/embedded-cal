// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]

// FIXME: Change to public as part of refactoring
mod hash;
pub use hash::sha2::test_hash_algorithm_sha256;
mod hmac;
pub use hmac::sha2::test_hmac_sha256;
mod hkdf;
pub use hkdf::sha2::test_hkdf_sha256;

pub mod aead;
pub mod dh;
pub use hash::sha3;

pub use aead::{
    test_aead_aesccm_16_64_128, test_aead_aesccm_16_64_256, test_aead_aesgcm_128,
    test_aead_aesgcm_256,
};
