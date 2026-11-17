// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Traits describing hardware that performs complete ECDSA operations on an already hashed
//! message.
//!
//! Hashing the message and encoding are left to the caller; deriving a public key is done through
//! [`EcPrimitives::multiply_scalar_point()`].
//!
//! Like the [`ec`][super::ec] plumbing, this is split by curve: ECDSA is an extension of each
//! curve's [`EcPrimitives`], so keys and signature components are that curve's
//! [`Scalar`][EcPrimitives::Scalar] and [`Point`][EcPrimitives::Point] types, and a back-end can
//! keep private keys resident in hardware rather than exposing their bytes. Callers reach it
//! through the same accessors, e.g. `cal.p256().ecdsa_sign(…)`.
//!
//! Only the short-Weierstrass curves of [`Ec`] take part. EdDSA (on the Edwards forms of
//! Curve25519 and Curve448) is a different algorithm and would get its own trait.

use super::ec::{Curve, Ec, EcPrimitives, P256, P384};

/// Trait indicating which curves of an [`Ec`] implementation provide ECDSA.
///
/// This has no items of its own: whether ECDSA is usable on a curve is
/// [`EcdsaPrimitives::HAS_ECDSA`] of that curve's primitives. (Like [`Ec`], it therefore has no
/// overall `SUPPORTED` constant).
pub trait Ecdsa:
    Ec<PrimitivesP256: EcdsaPrimitives<P256>, PrimitivesP384: EcdsaPrimitives<P384>>
{
}

/// ECDSA on the curve `C`, using the [`EcPrimitives`] types of that curve.
///
/// All byte slices are big-endian. Digests must be exactly as long as the curve's scalars (32
/// bytes for P-256, 48 bytes for P-384), which is the length of the hash function the curve is
/// paired with in COSE; implementations may panic on other lengths.
pub trait EcdsaPrimitives<C: Curve>: EcPrimitives<C> {
    /// Indicates whether the ECDSA functions are available (otherwise they panic).
    const HAS_ECDSA: bool;

    /// Generates a fresh private scalar `d`, uniformly random in `1..n`.
    fn ecdsa_generate(&mut self) -> Self::Scalar {
        panic!("user disregarded HAS_ECDSA=false")
    }

    /// Produces a raw `(r, s)` ECDSA signature over digest `h` with private scalar `d`.
    ///
    /// `d` must be in `1..n`; implementations may panic otherwise.
    ///
    /// The implementation picks the per-signature nonce itself, and retries with a new one when
    /// the nonce turns out to be unusable.
    fn ecdsa_sign(&mut self, d: &Self::Scalar, h: &[u8]) -> (Self::Scalar, Self::Scalar) {
        let _ = (d, h);
        panic!("user disregarded HAS_ECDSA=false")
    }

    /// Verifies a raw `(r, s)` ECDSA signature over digest `h` against public key `q`.
    ///
    /// `r` and `s` must be in `1..n`; implementations may panic otherwise (callers that take
    /// them from untrusted input check this first).
    fn ecdsa_verify(
        &mut self,
        q: &Self::Point,
        h: &[u8],
        r: &Self::Scalar,
        s: &Self::Scalar,
    ) -> Result<(), crate::SignatureInvalid> {
        let _ = (q, h, r, s);
        panic!("user disregarded HAS_ECDSA=false")
    }
}
