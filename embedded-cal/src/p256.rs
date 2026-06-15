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

// Exponent (p+1)/4 for modular square root (P-256: p ≡ 3 mod 4)
const SQRT_EXP: [u32; 8] = [
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0xC000_0000,
    0x3FFF_FFFF,
];

pub fn bytes_to_words(b: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for i in 0..8 {
        w[7 - i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
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

fn sub256(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut borrow: i64 = 0;
    for i in 0..8 {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        r[i] = d as u32;
        borrow = if d < 0 { 1 } else { 0 };
    }
    r
}

fn add_mod(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut carry: u64 = 0;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        r[i] = s as u32;
        carry = s >> 32;
    }
    if carry > 0 || ge(&r, &P) {
        sub256(&r, &P)
    } else {
        r
    }
}

fn mul_mod(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let cur = t[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
            t[i + j] = cur as u32;
            carry = cur >> 32;
        }
        t[i + 8] = carry as u32;
    }
    reduce_p256(&t)
}

// NIST FIPS 186-4 Appendix D.2.3 fast reduction for P-256.
fn reduce_p256(t: &[u32; 16]) -> [u32; 8] {
    let c = |i: usize| t[i] as i64;

    let mut acc = [0i64; 8];
    acc[0] = c(0) + c(8) + c(9) - c(11) - c(12) - c(13) - c(14);
    acc[1] = c(1) + c(9) + c(10) - c(12) - c(13) - c(14) - c(15);
    acc[2] = c(2) + c(10) + c(11) - c(13) - c(14) - c(15);
    acc[3] = c(3) + 2 * c(11) + 2 * c(12) + c(13) - c(15) - c(8) - c(9);
    acc[4] = c(4) + 2 * c(12) + 2 * c(13) + c(14) - c(9) - c(10);
    acc[5] = c(5) + 2 * c(13) + 2 * c(14) + c(15) - c(10) - c(11);
    acc[6] = c(6) + 3 * c(14) + 2 * c(15) + c(13) - c(8) - c(9);
    acc[7] = c(7) + 3 * c(15) + c(8) - c(10) - c(11) - c(12) - c(13);

    let mut r = [0u32; 8];
    let mut carry: i64 = 0;
    for i in 0..8 {
        let v = acc[i] + carry;
        r[i] = v as u32;
        carry = v >> 32;
    }

    // Absorb residual carry: 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p).
    for _ in 0..4 {
        if carry == 0 {
            break;
        }
        let adj = carry;
        let mut acc2 = [0i64; 8];
        for i in 0..8 {
            acc2[i] = r[i] as i64;
        }
        acc2[0] += adj;
        acc2[3] -= adj;
        acc2[6] -= adj;
        acc2[7] += adj;
        carry = 0;
        for i in 0..8 {
            let v = acc2[i] + carry;
            r[i] = v as u32;
            carry = v >> 32;
        }
    }

    for _ in 0..2 {
        if ge(&r, &P) {
            r = sub256(&r, &P);
        } else {
            break;
        }
    }
    r
}

fn pow_mod(base: &[u32; 8], exp: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    result[0] = 1;
    let mut base = *base;
    for mut word in exp.iter().copied() {
        for _ in 0..32 {
            if word & 1 != 0 {
                result = mul_mod(&result, &base);
            }
            base = mul_mod(&base, &base);
            word >>= 1;
        }
    }
    result
}

// Recover a y coordinate from the compact (x-only) P-256 representation.
// Either square root is accepted because for ECDH the shared secret is the
// x-coordinate of the result point, which is the same for both roots.
pub fn p256_recover_y(x_bytes: &[u8; 32]) -> Result<[u8; 32], crate::ImportError> {
    let x = bytes_to_words(x_bytes);

    if ge(&x, &P) {
        return Err(crate::ImportError);
    }

    // a = p - 3 (since P-256 coefficient a = -3)
    let a = sub256(&P, &[3, 0, 0, 0, 0, 0, 0, 0]);
    let x2 = mul_mod(&x, &x);
    let x3 = mul_mod(&x2, &x);
    let ax = mul_mod(&a, &x);
    let rhs = add_mod(&add_mod(&x3, &ax), &B);

    // y = rhs^((p+1)/4) mod p
    let y = pow_mod(&rhs, &SQRT_EXP);

    if mul_mod(&y, &y) != rhs {
        return Err(crate::ImportError);
    }

    Ok(words_to_bytes(&y))
}
