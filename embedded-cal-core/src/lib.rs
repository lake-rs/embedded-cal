#![no_std]

mod hash;
mod hmac;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use hash::{HashAlgorithm, HashProvider, NoHashAlgorithms, test_hash_algorithm_sha256};
pub use hmac::{HmacAlgorithm, HmacProvider, NoHmacAlgorithms, test_hmac_algorithm_hmacsha256};

pub trait Cal: HashProvider + HmacProvider {}
