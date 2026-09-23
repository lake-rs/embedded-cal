// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Test vectors and functions for various aspects of embedded-cal
//!
//! While the main contribution of this crate is having the test vectors, they are accompanied by
//! functions by which it can be evaluated whether or not an implementation performs the operations
//! correctly.
//!
//! In the interest of simplicity, the tests panic: Those tests failing is enough of a rare
//! occurrence that panic information will suffice, compared to more elaborate returning of results
//! (which would enable continuing after a failed instance).
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

pub mod rng;
