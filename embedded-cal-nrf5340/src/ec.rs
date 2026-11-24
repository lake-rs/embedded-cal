// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! # Elliptic curve arithmetic on the PKA
//!
//! The CC312 PKA has no point operations; everything here is composed from fully reduced modular
//! additions, subtractions, multiplications and exponentiations.
//!
//! * P-256 scalar multiplication is a Montgomery ladder over the complete projective addition
//!   formula of Renes, Costello and Batina ("Complete addition formulas for prime order elliptic
//!   curves", 2016, Algorithm 1). Being complete, the same formula also doubles and handles the
//!   point at infinity, so every scalar bit costs exactly one addition and one doubling.
//! * X25519 and X448 use the RFC 7748 Montgomery ladder.
//!
//! In both ladders, scalar bits only select *which registers* an operation acts on (through
//! [`cswap`] on register indices); the sequence of PKA operations does not depend on the scalar.
//! Inversion is done by Fermat exponentiation (`z^(p-2)`) with the PKA's ModExp, whose exponent
//! is the public constant p-2, so it is also scalar independent.
//!
//! Barrett tags (register NP) are precomputed with the formula of `PkaCalcNpIntoPkaReg()` for a
//! 64-bit PKA word with 8 extra bits: `floor(2^215 / ceil(N / 2^(len(N)-144)))`. For P-256 and
//! Curve25519 this matches the tags in the CC312 runtime's domain tables.

use crate::Nrf5340Cal;
use crate::pka::{Pka, cswap};
use embedded_cal::util::p256::P;

// --- Constants (little-endian 32-bit words) ---

/// Barrett tag shared by the P-256 field prime and the P-256 group order.
pub(crate) const P256_NP: [u32; 3] = [0xFFFF_FFFF, 0x0000_007F, 0x0000_0080];
/// Barrett tag shared by 2^255 - 19 and 2^448 - 2^224 - 1.
const MONTGOMERY_NP: [u32; 3] = [0x0000_0000, 0x0000_0000, 0x0000_0080];

/// a = -3 mod p
const P256_A: [u32; 8] = [
    0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
];
/// 3b mod p
const P256_B3: [u32; 8] = [
    0x777720E2, 0xB36AB4BA, 0x64FB12E2, 0x2F571411, 0x63C99435, 0x1BC33800, 0xFEAFBBB6, 0x1052A18A,
];
const P256_P_MINUS_2: [u32; 8] = [
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
];

const X25519_P: [u32; 8] = [
    0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
];
const X25519_P_MINUS_2: [u32; 8] = [
    0xFFFFFFEB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
];
/// (486662 - 2) / 4
const X25519_A24: u32 = 121665;

const X448_P: [u32; 14] = [
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];
const X448_P_MINUS_2: [u32; 14] = [
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];
/// (156326 - 2) / 4
const X448_A24: u32 = 39081;

// --- P-256 register allocation (0 and 1 are N and NP) ---

const W_A: u8 = 2;
const W_B3: u8 = 3;
/// Four point triples (X, Y, Z) that the ladder rotates through.
const W_LADDER: [[u8; 3]; 4] = [[4, 5, 6], [7, 8, 9], [10, 11, 12], [13, 14, 15]];
/// Temporaries of the addition formula.
const W_T: [u8; 6] = [16, 17, 18, 19, 20, 21];
/// Input point of a ladder.
const W_BASE: [u8; 3] = [22, 23, 24];
const W_ZINV: u8 = 28;
const W_EXP: u8 = 29;

type Triple = [u8; 3];

impl Pka<'_> {
    /// (X3:Y3:Z3) = (X1:Y1:Z1) + (X2:Y2:Z2), RCB16 Algorithm 1 with A = a and B3 = 3b.
    ///
    /// Complete: valid for doubling (identical inputs) and for the point at infinity (0:1:0). The
    /// output triple must be distinct from both inputs.
    fn rcb_add(&self, p: Triple, q: Triple, r: Triple) {
        let [x1, y1, z1] = p;
        let [x2, y2, z2] = q;
        let [x3, y3, z3] = r;
        let [t0, t1, t2, t3, t4, t5] = W_T;
        let (a, b3) = (W_A, W_B3);

        self.mod_mul(t0, x1, x2);
        self.mod_mul(t1, y1, y2);
        self.mod_mul(t2, z1, z2);
        self.mod_add(t3, x1, y1);
        self.mod_add(t4, x2, y2);
        self.mod_mul(t3, t3, t4);
        self.mod_add(t4, t0, t1);
        self.mod_sub(t3, t3, t4);
        self.mod_add(t4, x1, z1);
        self.mod_add(t5, x2, z2);
        self.mod_mul(t4, t4, t5);
        self.mod_add(t5, t0, t2);
        self.mod_sub(t4, t4, t5);
        self.mod_add(t5, y1, z1);
        self.mod_add(x3, y2, z2);
        self.mod_mul(t5, t5, x3);
        self.mod_add(x3, t1, t2);
        self.mod_sub(t5, t5, x3);
        self.mod_mul(z3, a, t4);
        self.mod_mul(x3, b3, t2);
        self.mod_add(z3, x3, z3);
        self.mod_sub(x3, t1, z3);
        self.mod_add(z3, t1, z3);
        self.mod_mul(y3, x3, z3);
        self.mod_add(t1, t0, t0);
        self.mod_add(t1, t1, t0);
        self.mod_mul(t2, a, t2);
        self.mod_mul(t4, b3, t4);
        self.mod_add(t1, t1, t2);
        self.mod_sub(t2, t0, t2);
        self.mod_mul(t2, a, t2);
        self.mod_add(t4, t4, t2);
        self.mod_mul(t0, t1, t4);
        self.mod_add(y3, y3, t0);
        self.mod_mul(t0, t5, t4);
        self.mod_mul(x3, t3, x3);
        self.mod_sub(x3, x3, t0);
        self.mod_mul(t0, t3, t1);
        self.mod_mul(z3, t5, z3);
        self.mod_add(z3, z3, t0);
    }

    /// Prepares the PKA for P-256 field arithmetic.
    fn p256_setup(&self) {
        self.set_modulus(&P, &P256_NP);
        self.load(W_A, &P256_A);
        self.load(W_B3, &P256_B3);
    }

    /// Loads an affine point (big-endian coordinates) as (x:y:1) into [`W_BASE`].
    fn p256_load_base(&self, x: &[u8; 32], y: &[u8; 32]) {
        self.load_be(W_BASE[0], x);
        self.load_be(W_BASE[1], y);
        self.set_word(W_BASE[2], 1);
    }

    /// Computes k * [`W_BASE`] for a big-endian scalar k; returns the triple holding the
    /// projective result.
    fn p256_ladder(&self, k: &[u8; 32]) -> Triple {
        let [mut r0, mut r1, mut s, mut d] = W_LADDER;

        // R0 = point at infinity (0:1:0), R1 = base
        self.set_word(r0[0], 0);
        self.set_word(r0[1], 1);
        self.set_word(r0[2], 0);
        for i in 0..3 {
            self.copy(r1[i], W_BASE[i]);
        }

        for i in (0..256).rev() {
            let bit = (k[31 - i / 8] >> (i % 8)) & 1;
            for j in 0..3 {
                cswap(&mut r0[j], &mut r1[j], bit);
            }
            // (R0, R1) <- (2 R0, R0 + R1); recycle the old triples as next round's outputs.
            self.rcb_add(r0, r1, s);
            self.rcb_add(r0, r0, d);
            (r0, r1, s, d) = (d, s, r0, r1);
            for j in 0..3 {
                cswap(&mut r0[j], &mut r1[j], bit);
            }
        }

        r0
    }

    /// Converts a projective point to affine big-endian coordinates.
    ///
    /// Returns `None` for the point at infinity.
    fn p256_affine(&self, p: Triple) -> Option<([u8; 32], [u8; 32])> {
        // Infinity is detected from the result rather than by reading Z first, which saves a
        // read-back.
        let [out_x, out_y, ..] = W_T;
        self.load(W_EXP, &P256_P_MINUS_2);
        self.mod_exp(W_ZINV, p[2], W_EXP);
        self.mod_mul(out_x, p[0], W_ZINV);
        self.mod_mul(out_y, p[1], W_ZINV);

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        self.read_be(out_x, &mut x);
        self.read_be(out_y, &mut y);

        // For the point at infinity Z = 0, so Z^(p-2) = 0 and both coordinates come out 0; (0, 0)
        // is not on P-256 (b != 0), so this identifies infinity exactly.
        if x == [0; 32] && y == [0; 32] {
            return None;
        }
        Some((x, y))
    }

    /// RFC 7748 Montgomery ladder; `scalar` and `u` are little-endian, `u` reduced mod p, and the
    /// scalar already clamped. Writes the resulting u-coordinate (little-endian) into `out`.
    fn montgomery_ladder(
        &self,
        p_minus_2: &[u32],
        a24: u32,
        scalar: &[u8],
        scalar_bits: usize,
        u: &[u8],
        out: &mut [u8],
    ) {
        const A24: u8 = 2;
        const X1: u8 = 3;
        const A: u8 = 8;
        const AA: u8 = 9;
        const B: u8 = 10;
        const BB: u8 = 11;
        const E: u8 = 12;
        const C: u8 = 13;
        const D: u8 = 14;
        const DA: u8 = 15;
        const CB: u8 = 16;
        const ZINV: u8 = 17;
        const RES: u8 = 18;
        const EXP: u8 = 19;
        let (mut x2, mut z2, mut x3, mut z3) = (4u8, 5u8, 6u8, 7u8);

        self.set_word(A24, a24);
        self.load_le(X1, u);
        self.set_word(x2, 1);
        self.set_word(z2, 0);
        self.copy(x3, X1);
        self.set_word(z3, 1);

        let mut swap = 0u8;
        for t in (0..scalar_bits).rev() {
            let k_t = (scalar[t / 8] >> (t % 8)) & 1;
            swap ^= k_t;
            cswap(&mut x2, &mut x3, swap);
            cswap(&mut z2, &mut z3, swap);
            swap = k_t;

            self.mod_add(A, x2, z2);
            self.mod_mul(AA, A, A);
            self.mod_sub(B, x2, z2);
            self.mod_mul(BB, B, B);
            self.mod_sub(E, AA, BB);
            self.mod_add(C, x3, z3);
            self.mod_sub(D, x3, z3);
            self.mod_mul(DA, D, A);
            self.mod_mul(CB, C, B);
            self.mod_add(x3, DA, CB);
            self.mod_mul(x3, x3, x3);
            self.mod_sub(z3, DA, CB);
            self.mod_mul(z3, z3, z3);
            self.mod_mul(z3, X1, z3);
            self.mod_mul(x2, AA, BB);
            self.mod_mul(z2, A24, E);
            self.mod_add(z2, AA, z2);
            self.mod_mul(z2, E, z2);
        }
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);

        self.load(EXP, p_minus_2);
        self.mod_exp(ZINV, z2, EXP);
        self.mod_mul(RES, x2, ZINV);
        self.read_le(RES, out);
    }
}

impl Nrf5340Cal {
    /// P-256 scalar multiplication k * (px, py) with big-endian scalar and coordinates.
    ///
    /// The point must be on the curve with coordinates below p. Returns (0, 0) if the result is
    /// the point at infinity (which only happens for k ≡ 0 mod n).
    pub(crate) fn p256_mul(
        &mut self,
        k: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let pka = self.pka(256);
        pka.p256_setup();
        pka.p256_load_base(px, py);
        let r = pka.p256_ladder(k);
        pka.p256_affine(r).unwrap_or(([0; 32], [0; 32]))
    }

    /// X25519 (RFC 7748) on a clamped scalar and a u-coordinate with its top bit cleared.
    pub(crate) fn x25519_mul(&mut self, scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        let mut u_words = le_words::<8>(u);
        reduce_once(&mut u_words, &X25519_P);

        let mut out = [0u8; 32];
        let pka = self.pka(255);
        pka.set_modulus(&X25519_P, &MONTGOMERY_NP);
        pka.montgomery_ladder(
            &X25519_P_MINUS_2,
            X25519_A24,
            scalar,
            255,
            &words_le::<8, 32>(&u_words),
            &mut out,
        );
        out
    }

    /// X448 (RFC 7748) on a clamped scalar.
    pub(crate) fn x448_mul(&mut self, scalar: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
        let mut u_words = le_words::<14>(u);
        reduce_once(&mut u_words, &X448_P);

        let mut out = [0u8; 56];
        let pka = self.pka(448);
        pka.set_modulus(&X448_P, &MONTGOMERY_NP);
        pka.montgomery_ladder(
            &X448_P_MINUS_2,
            X448_A24,
            scalar,
            448,
            &words_le::<14, 56>(&u_words),
            &mut out,
        );
        out
    }
}

// --- Small CPU-side helpers on public values ---

fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    for (w, c) in w.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*c);
    }
    w
}

fn words_le<const N: usize, const B: usize>(words: &[u32; N]) -> [u8; B] {
    let mut b = [0u8; B];
    for (c, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *c = w.to_le_bytes();
    }
    b
}

/// Compares little-endian word arrays: a >= b.
pub(crate) fn ge_words(a: &[u32], b: &[u32]) -> bool {
    for (x, y) in a.iter().zip(b).rev() {
        if x != y {
            return x > y;
        }
    }
    true
}

/// a -= b on little-endian word arrays (wrapping).
pub(crate) fn sub_words(a: &mut [u32], b: &[u32]) {
    let mut borrow = false;
    for (x, y) in a.iter_mut().zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(borrow as u32);
        *x = d;
        borrow = b1 || b2;
    }
}

/// Reduces a value below 2p into [0, p).
pub(crate) fn reduce_once(a: &mut [u32], p: &[u32]) {
    if ge_words(a, p) {
        sub_words(a, p);
    }
}
