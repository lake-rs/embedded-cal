// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// P-256 field arithmetic shared by hardware DH back-ends.
//
// All [u32; 8] arrays use little-endian word order: index 0 is the least-significant word.
// Big-endian byte arrays (as used in COSE / CBOR) are converted via `bytes_to_words` /
// `words_to_bytes`.

// p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
pub const P: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

pub const P256_ORDER: [u32; 8] = [
    0xFC63_2551,
    0xF3B9_CAC2,
    0xA717_9E84,
    0xBCE6_FAAD,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0xFFFF_FFFF,
];

pub const B: [u32; 8] = [
    0x27D2_604B,
    0x3BCE_3C3E,
    0xCC53_B0F6,
    0x651D_06B0,
    0x7698_86BC,
    0xB3EB_BD55,
    0xAA3A_93E7,
    0x5AC6_35D8,
];

// P-256 generator point G = (Gx, Gy) in big-endian bytes (NIST FIPS 186-4 D.1.2.3).
pub const P256_GX_BYTES: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
pub const P256_GY_BYTES: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

// Same in little-endian word order (index 0 = least-significant word), matching P, P256_ORDER, B.
pub const P256_GX: [u32; 8] = bytes_to_words(&P256_GX_BYTES);
pub const P256_GY: [u32; 8] = bytes_to_words(&P256_GY_BYTES);

// Exponent (p+1)/4 for modular square root (P-256: p ≡ 3 mod 4)
pub const SQRT_EXP: [u32; 8] = [
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0xC000_0000,
    0x3FFF_FFFF,
];

pub const fn bytes_to_words(b: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        w[7 - i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        i += 1;
    }
    w
}

pub fn words_to_bytes(w: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[7 - i].to_be_bytes());
    }
    out
}

pub fn ge(a: &[u32; 8], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

const fn sub256(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut borrow: i64 = 0;
    let mut i = 0;
    while i < 8 {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        r[i] = d as u32;
        borrow = if d < 0 { 1 } else { 0 };
        i += 1;
    }
    r
}

pub const P256_COEF_A: [u32; 8] = sub256(&P, &[3, 0, 0, 0, 0, 0, 0, 0]);
