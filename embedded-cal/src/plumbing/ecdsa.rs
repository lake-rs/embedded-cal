// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Traits describing hardware that performs complete ECDSA operations on an already hashed
//! message.
//!
//! Hashing the message, key handling and encoding are left to the caller; deriving a public key is
//! done through [`super::ec::EcPrimitives::multiply_scalar_point()`].

/// Trait indicating that there is hardware support for ECDSA on P-256.
///
/// All byte arrays are big-endian.
pub trait Ecdsa {
    /// Whether this trait is actually supported. See [`Plumbing`][super::Plumbing] docs for
    /// rationale.
    const SUPPORTED: bool;

    /// Generates a fresh private scalar `d`, uniformly random in `1..n`.
    fn ecdsa_p256_generate(&mut self) -> [u8; 32] {
        panic!("user disregarded SUPPORTED=false")
    }

    /// Produces a raw `(r, s)` ECDSA signature over digest `h` with private scalar `d`.
    ///
    /// The implementation picks the per-signature nonce itself, and retries with a new one when
    /// the nonce turns out to be unusable.
    fn ecdsa_p256_sign(&mut self, d: &[u8; 32], h: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let _ = (d, h);
        panic!("user disregarded SUPPORTED=false")
    }

    /// Verifies a raw `(r, s)` ECDSA signature over digest `h` against public key `(qx, qy)`.
    fn ecdsa_p256_verify(
        &mut self,
        qx: &[u8; 32],
        qy: &[u8; 32],
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<(), crate::SignatureInvalid> {
        let _ = (qx, qy, h, r, s);
        panic!("user disregarded SUPPORTED=false")
    }
}
