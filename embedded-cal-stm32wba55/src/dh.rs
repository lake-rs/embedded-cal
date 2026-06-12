use rand_core::Rng;

// P-256 curve constants (little-endian word order: LSW at index 0)

const P256_COEF_A_MAGNITUDE: [u32; 8] = [0x0000_0003, 0, 0, 0, 0, 0, 0, 0];
#[repr(u32)]
enum CoefSign {
    _Positive = 0, // unused: P-256 coefficient a is always negative
    Negative = 1,
}

// p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
const P: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

const B: [u32; 8] = [
    0x27D2_604B,
    0x3BCE_3C3E,
    0xCC53_B0F6,
    0x651D_06B0,
    0x7698_86BC,
    0xB3EB_BD55,
    0xAA3A_93E7,
    0x5AC6_35D8,
];

const P256_ORDER: [u32; 8] = [
    0xFC63_2551,
    0xF3B9_CAC2,
    0xA717_9E84,
    0xBCE6_FAAD,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0xFFFF_FFFF,
];

const P256_GX: [u32; 8] = [
    0xd898_c296,
    0xf4a1_3945,
    0x2deb_33a0,
    0x7703_7d81,
    0x63a4_40f2,
    0xf8bc_e6e5,
    0xe12c_4247,
    0x6b17_d1f2,
];

const P256_GY: [u32; 8] = [
    0x37bf_51f5,
    0xcbb6_4068,
    0x6b31_5ece,
    0x2bce_3357,
    0x7c0f_9e16,
    0x8ee7_eb4a,
    0xfe1a_7f9b,
    0x4fe3_42e2,
];

// PKA RAM slot indices for ECC scalar multiplication (STM32WBA55 RM0493)

const RAM_N_LEN: usize = 0;
const RAM_P_LEN: usize = 2;
const RAM_A_SIGN: usize = 4;
const RAM_A: usize = 6;
const RAM_B: usize = 72;
const RAM_P: usize = 802;
const RAM_POINT_X: usize = 94;
const RAM_POINT_Y: usize = 28;
const RAM_N: usize = 738;
const RAM_K: usize = 936;
const RAM_RESULT_Y: usize = 116;

const PKA_MODE_ECC_MULT: u8 = 0b10_0000;
const PKA_RAM_WORDS: usize = 667;

// Convert big-endian bytes to/from little-endian words (the single representation used everywhere).
fn bytes_to_words(b: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for i in 0..8 {
        w[7 - i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    w
}

fn words_to_bytes(w: &[u32; 8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..8 {
        b[i * 4..i * 4 + 4].copy_from_slice(&w[7 - i].to_be_bytes());
    }
    b
}

// P-256 modular arithmetic for point decompression (compact public-key import).
// All [u32; 8] values use little-endian word order (index 0 = LSW).

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

fn ge(a: &[u32; 8], b: &[u32; 8]) -> bool {
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
fn p256_recover_y(x_bytes: &[u8; 32]) -> Result<[u8; 32], embedded_cal::ImportError> {
    let x = bytes_to_words(x_bytes);

    if ge(&x, &P) {
        return Err(embedded_cal::ImportError);
    }

    // a = p - 3 (since P-256 coefficient a = -3)
    let a = sub256(&P, &[3, 0, 0, 0, 0, 0, 0, 0]);
    let x2 = mul_mod(&x, &x);
    let x3 = mul_mod(&x2, &x);
    let ax = mul_mod(&a, &x);
    let rhs = add_mod(&add_mod(&x3, &ax), &B);

    // y = rhs^((p+1)/4) mod p  — valid since p ≡ 3 (mod 4)
    let y = pow_mod(&rhs, &SQRT_EXP);

    if mul_mod(&y, &y) != rhs {
        return Err(embedded_cal::ImportError);
    }

    Ok(words_to_bytes(&y))
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DhAlgorithm {
    EcdhP256,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::EcdhP256 => 32,
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        match curve.into() {
            1 => Some(DhAlgorithm::EcdhP256),
            _ => None,
        }
    }
}

pub struct SecretKey {
    alg: DhAlgorithm,
    scalar: [u8; 32],
}

pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

pub struct PublicKey {
    alg: DhAlgorithm,
    x: [u8; 32],
    y: [u8; 32],
}

pub struct SharedSecret([u8; 32]);

impl super::Stm32wba55Cal {
    fn pka_zero_ram(&mut self) {
        for i in 0..PKA_RAM_WORDS {
            self.pka.ram(i).write_value(0);
        }
    }

    // Write a 256-bit value (LE word order, LSW first) to PKA RAM.
    fn pka_write_field(&mut self, start: usize, words: &[u32; 8]) {
        for (i, &word) in words.iter().enumerate() {
            self.pka.ram(start + i).write_value(word);
        }
    }

    // Read a 256-bit value from PKA RAM into LE word order.
    fn pka_read_field(&mut self, start: usize) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (i, w) in words.iter_mut().enumerate() {
            *w = self.pka.ram(start + i).read();
        }
        words
    }

    pub(super) fn pka_ecc_mult(
        &mut self,
        scalar: &[u32; 8],
        point_x: &[u32; 8],
        point_y: &[u32; 8],
    ) -> ([u32; 8], [u32; 8]) {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_N_LEN).write_value(256);
        self.pka.ram(RAM_P_LEN).write_value(256);
        self.pka
            .ram(RAM_A_SIGN)
            .write_value(CoefSign::Negative as u32);
        self.pka_write_field(RAM_A, &P256_COEF_A_MAGNITUDE);
        self.pka_write_field(RAM_B, &B);
        self.pka_write_field(RAM_P, &P);
        self.pka_write_field(RAM_N, &P256_ORDER);
        self.pka_write_field(RAM_POINT_X, point_x);
        self.pka_write_field(RAM_POINT_Y, point_y);
        self.pka_write_field(RAM_K, scalar);

        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(PKA_MODE_ECC_MULT);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        let sr = self.pka.sr().read();
        // addrerrf / ramerrf indicate address or RAM access faults.
        // Do NOT check pka.ram(160): that word is only valid for the point-check
        // opcode (0b101000), not for scalar multiplication.
        debug_assert!(
            !sr.addrerrf() && !sr.ramerrf(),
            "PKA ECC scalar multiplication failed (SR error flags set)"
        );

        let result_x = self.pka_read_field(RAM_POINT_X);
        let result_y = self.pka_read_field(RAM_RESULT_Y);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });

        (result_x, result_y)
    }
}

impl embedded_cal::DhProvider for super::Stm32wba55Cal {
    type Algorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            DhAlgorithm::EcdhP256 => loop {
                let mut scalar = [0u8; 32];
                // Error = Infallible for this RNG
                self.fill_bytes(&mut scalar);
                let w = bytes_to_words(&scalar);
                if w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                    return VisibleSecretKey(SecretKey { alg, scalar });
                }
            },
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secretkey.0.scalar
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let scalar: [u8; 32] = secret.try_into().map_err(|_| embedded_cal::ImportError)?;
        Ok(VisibleSecretKey(SecretKey { alg, scalar }))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        &public.x
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        let x: [u8; 32] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
        let y = p256_recover_y(&x)?;
        Ok(PublicKey { alg, x, y })
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        let (result_x, _) = self.pka_ecc_mult(
            &bytes_to_words(&private.scalar),
            &bytes_to_words(&public.x),
            &bytes_to_words(&public.y),
        );
        Ok(SharedSecret(words_to_bytes(&result_x)))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let (result_x, result_y) =
            self.pka_ecc_mult(&bytes_to_words(&private.scalar), &P256_GX, &P256_GY);
        PublicKey {
            alg: private.alg.clone(),
            x: words_to_bytes(&result_x),
            y: words_to_bytes(&result_y),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secret.0
    }
}
