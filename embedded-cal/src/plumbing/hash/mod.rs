//! Traits that describe how a hardware accelerator can assist in calculating SHA-2 hashes.
//!
//! As support for SHA-2 is commonly split by the variant's block size (SHA-224 and SHA-256 with
//! 512 bit block size use different hardware than SHA-384, SHA-512 and its truncated versions which have
//! 1024 bit block size), they split in [`Sha2Short`] and `Sha2Long` (currently unimplemented).

mod sha2short;
pub use sha2short::*;

pub trait Hash: Sha2Short {}

pub const SHA2SHORT_BLOCK_SIZE: usize = 64;

/// The maximum buffer needed to spool data for hashing through a back-end type.
///
/// This is a free function rather than a provided const method on the [`Hash`] trait simply
/// because const methods do not work in stable Rust.
///
/// This can be 0 if all the back-ends can take arbitrary slices, or if none are supported.
/// Implementations that create something equivalent to a `heapless::Vec` out of this and don't
/// need some minimal buffer internally will suffer some small per-state overhead (an unused size
/// field in their struct). They could avoid this by applying some clever tricks with putting the
/// buffer in a possibly-zero-sized array if that is really an issue.
pub const fn hash_buffer_requirements<T: Hash>() -> usize {
    let for_sha2 = if <T as Sha2Short>::SUPPORTED {
        if T::FIRST_CHUNK_SIZE > SHA2SHORT_BLOCK_SIZE {
            T::FIRST_CHUNK_SIZE
        } else {
            SHA2SHORT_BLOCK_SIZE
        }
    } else {
        0
    };
    #[allow(
        clippy::let_and_return,
        reason = "this will become a maximum of multiple blocks above for different hashes"
    )]
    for_sha2
}
