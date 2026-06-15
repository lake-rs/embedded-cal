use embedded_cal::p256::{B, P, P256_ORDER, bytes_to_words, ge, p256_recover_y, words_to_bytes};
use rand_core::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// P-256 curve constants (little-endian word order: LSW at index 0)

const P256_COEF_A_MAGNITUDE: [u32; 8] = [0x0000_0003, 0, 0, 0, 0, 0, 0, 0];
#[repr(u32)]
enum CoefSign {
    _Positive = 0, // unused: P-256 coefficient a is always negative
    Negative = 1,
}

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

#[derive(PartialEq, Eq, Debug, Clone, Zeroize)]
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    alg: DhAlgorithm,
    scalar: [u8; 32],
}

#[derive(Zeroize)]
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

#[derive(Zeroize, ZeroizeOnDrop)]
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

        // Zero PKA RAM to clear the private scalar (RAM_K) and result coordinates.
        self.pka_zero_ram();

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
        let mut scalar_words = bytes_to_words(&private.scalar);
        let (result_x, _) = self.pka_ecc_mult(
            &scalar_words,
            &bytes_to_words(&public.x),
            &bytes_to_words(&public.y),
        );
        scalar_words.zeroize();
        Ok(SharedSecret(words_to_bytes(&result_x)))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let mut scalar_words = bytes_to_words(&private.scalar);
        let (result_x, result_y) = self.pka_ecc_mult(&scalar_words, &P256_GX, &P256_GY);
        scalar_words.zeroize();
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
