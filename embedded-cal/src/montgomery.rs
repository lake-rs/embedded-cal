// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Scalar and coordinate fixups for the RFC 7748 curves (X25519 and X448).
//!
//! The [EC plumbing][crate::plumbing::ec::EcPrimitives] deliberately does not clamp its operands,
//! so callers that feed it RFC 7748 key material have to apply these themselves. They live here
//! rather than in a back-end because every user of the plumbing layer needs the same ones.

/// Applies the `decodeScalar25519` fixups of [RFC 7748 section 5] to a private key.
pub fn clamp_x25519(k: &mut [u8; 32]) {
    k[0] &= 0xF8;
    k[31] = (k[31] | 0x40) & 0x7F;
}

/// Applies the `decodeScalar448` fixups of [RFC 7748 section 5] to a private key.
pub fn clamp_x448(k: &mut [u8; 56]) {
    k[0] &= 0xFC;
    k[55] |= 0x80;
}

/// Clears the unused most significant bit of an X25519 u-coordinate.
///
/// [RFC 7748 section 5] mandates this when decoding a u-coordinate; it has no X448 counterpart
/// because that curve's field elements fill their 56 bytes exactly.
pub fn mask_u_x25519(u: &mut [u8; 32]) {
    u[31] &= 0x7F;
}
