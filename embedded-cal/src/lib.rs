#![no_std]

pub mod empty;

mod aead;
mod hash;
mod hmac;
mod rng;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use aead::{
    AadGenerator, AeadAlgorithm, AeadProvider, DecryptionFailed,
    test_aead_algorithm_aesccm_16_64_128,
};
pub use hash::{HashAlgorithm, HashProvider, test_hash_algorithm_sha256};
pub use hmac::{HmacAlgorithm, HmacProvider, test_hmac_algorithm_hmacsha256};
pub use rng::test_tryrng;

pub trait Cal: HashProvider + HmacProvider + AeadProvider {}
