// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Trait describing hardware support for ECDSA sign/verify.

/// All byte arrays are big-endian.
pub trait EcdsaP256 {
    /// Computes `scalar * (px, py)` on the P-256 curve.
    ///
    /// Used both for deriving a public key from a private key (passing the generator point as
    /// `(px, py)`) and for scalar multiplication in general.
    fn p256_mult(
        &mut self,
        scalar: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]);

    /// Produces a raw `(r, s)` ECDSA signature over digest `h`, using private scalar `d` and
    /// per-signature nonce `k`.
    ///
    /// Returns `None` if `k` turned out to be unusable (no modular inverse, or the resulting `r`
    /// or `s` reduced to zero); per FIPS 186-5, the caller should resample `k` and retry.
    fn ecdsa_sign(
        &mut self,
        d: &[u8; 32],
        k: &[u8; 32],
        h: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 32])>;

    /// Verifies a raw `(r, s)` ECDSA signature over digest `h` against public key `(qx, qy)`.
    fn ecdsa_verify(
        &mut self,
        qx: &[u8; 32],
        qy: &[u8; 32],
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<(), crate::SignatureInvalid>;
}
