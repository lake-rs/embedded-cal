// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Constant-time helpers for secret data.
//!
//! Masks are `0xFF` for "true" and `0x00` for "false". Results are computed with arithmetic only,
//! never with branches or early exits on the data; [`black_box`] keeps the compiler from turning
//! the masks back into branches.

use core::hint::black_box;

/// The P-256 group order n, big-endian.
pub(crate) const P256_N_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// 2^256 mod n (= 2^256 - n), big-endian.
pub(crate) const P256_2_256_MOD_N_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x19, 0x05, 0x52, 0x58, 0xE8, 0x61, 0x7B, 0x0C, 0x46, 0x35, 0x3D, 0x03, 0x9C, 0xDA, 0xAF,
];

/// `0xFF` if all bytes of `a` are zero, else `0x00`.
pub(crate) fn is_zero_mask(a: &[u8]) -> u8 {
    let acc = black_box(a.iter().fold(0u8, |acc, &b| acc | b)) as u16;
    // acc = 0 wraps to 0xFFFF; any acc in 1..=255 stays below 0x100.
    (acc.wrapping_sub(1) >> 8) as u8
}

/// a - b for big-endian 256-bit numbers; returns the (wrapped) difference and a mask that is
/// `0xFF` if a < b.
pub(crate) fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let d = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        out[i] = d as u8;
        // A negative difference wraps to 0xFF01..=0xFFFF, so bit 15 is the borrow.
        borrow = d >> 15;
    }
    (out, 0u8.wrapping_sub(black_box(borrow as u8)))
}

/// `a` where `mask` is `0xFF`, `b` where it is `0x00`.
pub(crate) fn select(mask: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mask = black_box(mask);
    core::array::from_fn(|i| (a[i] & mask) | (b[i] & !mask))
}

/// `0xFF` if 0 < s < n.
pub(crate) fn p256_scalar_valid_mask(s: &[u8; 32]) -> u8 {
    let (_, below_n) = sub_be(s, &P256_N_BE);
    below_n & !is_zero_mask(s)
}

/// Reduces a 256-bit big-endian number mod n. As 2n > 2^256, one conditional subtraction
/// suffices.
pub(crate) fn p256_reduce_once(v: &[u8; 32]) -> [u8; 32] {
    let (d, below_n) = sub_be(v, &P256_N_BE);
    select(below_n, v, &d)
}
