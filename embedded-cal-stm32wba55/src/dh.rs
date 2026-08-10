// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::p256::{
    B, P, P256_GX, P256_GY, P256_ORDER, bytes_to_words, ge, p256_recover_y, words_to_bytes,
};
use rand_core::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// P-256 curve constants (little-endian word order: LSW at index 0)

const P256_COEF_A_MAGNITUDE: [u32; 8] = [0x0000_0003, 0, 0, 0, 0, 0, 0, 0];
#[repr(u32)]
enum CoefSign {
    _Positive = 0, // unused: P-256 coefficient a is always negative
    Negative = 1,
}

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
// Total PKA RAM size (RM0493 / ST HAL `stm32wbaxx_hal_pka.c`, `PKA->RAM[1334]`),
const PKA_RAM_WORDS: usize = 1334;

// PKA RAM slot indices for ECDSA-P256 signature generation (PKA_MODE_ECDSA_SIGN = 0x24).
const RAM_SIGN_PRIVATE_D: usize = 714;
const RAM_SIGN_HASH_E: usize = 762;
const RAM_SIGN_OUT_ERROR: usize = 760;
const RAM_SIGN_OUT_R: usize = 204;
const RAM_SIGN_OUT_S: usize = 226;

// PKA RAM slot indices for ECDSA-P256 signature verification (PKA_MODE_ECDSA_VERIFY = 0x26).
const RAM_VERIF_ORDER_NB_BITS: usize = 2;
const RAM_VERIF_MOD_NB_BITS: usize = 50;
const RAM_VERIF_A_SIGN: usize = 26;
const RAM_VERIF_A: usize = 28;
const RAM_VERIF_MOD_P: usize = 52;
const RAM_VERIF_POINT_X: usize = 158;
const RAM_VERIF_POINT_Y: usize = 180;
const RAM_VERIF_PUBKEY_X: usize = 958;
const RAM_VERIF_PUBKEY_Y: usize = 980;
const RAM_VERIF_SIG_R: usize = 824;
const RAM_VERIF_SIG_S: usize = 538;
const RAM_VERIF_HASH_E: usize = 1002;
const RAM_VERIF_ORDER_N: usize = 802;
const RAM_VERIF_OUT_RESULT: usize = 116;

const PKA_MODE_ECDSA_SIGN: u8 = 0x24;
const PKA_MODE_ECDSA_VERIFY: u8 = 0x26;
// PKA "no error" / "signature valid" sentinel written to the mode's OUT_ERROR / OUT_RESULT slot
const PKA_NO_ERROR: u32 = 0xD60D;

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

    // Full ECDSA-P256 signature generation on the STM32WBA55 PKA (PKA_MODE_ECDSA_SIGN = 0x24,
    // "protected" i.e. side-channel-hardened per RM0493). `d` (private scalar), `k` (per-signature
    // nonce), and `h` (message digest) are little-endian word arrays (see `bytes_to_words`).
    // Returns `None` if the hardware reports the nonce was unusable (its signature generation
    // failed, e.g. r or s reduced to zero); per FIPS 186-5's signature generation algorithm, the
    // caller should resample `k` and retry. Zeroes all of PKA RAM (including the private scalar)
    // before returning either way.
    pub(super) fn pka_ecdsa_sign(
        &mut self,
        d: &[u32; 8],
        k: &[u32; 8],
        h: &[u32; 8],
    ) -> Option<([u32; 8], [u32; 8])> {
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
        self.pka_write_field(RAM_POINT_X, &P256_GX);
        self.pka_write_field(RAM_POINT_Y, &P256_GY);
        self.pka_write_field(RAM_K, k);
        self.pka_write_field(RAM_SIGN_HASH_E, h);
        self.pka_write_field(RAM_SIGN_PRIVATE_D, d);

        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(PKA_MODE_ECDSA_SIGN);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        let sr = self.pka.sr().read();
        debug_assert!(
            !sr.addrerrf() && !sr.ramerrf(),
            "PKA ECDSA sign failed (SR error flags set)"
        );

        // Per ST HAL's PKA_CheckError: OUT_ERROR != PKA_NO_ERROR means the operation needs to be
        // repeated (unusable nonce), not necessarily a hardware fault.
        let unusable_nonce = self.pka.ram(RAM_SIGN_OUT_ERROR).read() != PKA_NO_ERROR;
        let result = if unusable_nonce {
            None
        } else {
            let r = self.pka_read_field(RAM_SIGN_OUT_R);
            let s = self.pka_read_field(RAM_SIGN_OUT_S);
            Some((r, s))
        };

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        // Zero PKA RAM to clear the private key (RAM_SIGN_PRIVATE_D) and nonce (RAM_K).
        self.pka_zero_ram();

        result
    }

    // Full ECDSA-P256 signature verification on the STM32WBA55 PKA (PKA_MODE_ECDSA_VERIFY =
    // 0x26). `qx`/`qy` (public key), `r`/`s` (signature), and `h` (message digest) are
    // little-endian word arrays.
    pub(super) fn pka_ecdsa_verify(
        &mut self,
        qx: &[u32; 8],
        qy: &[u32; 8],
        h: &[u32; 8],
        r: &[u32; 8],
        s: &[u32; 8],
    ) -> Result<(), embedded_cal::SignatureInvalid> {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_VERIF_ORDER_NB_BITS).write_value(256);
        self.pka.ram(RAM_VERIF_MOD_NB_BITS).write_value(256);
        self.pka
            .ram(RAM_VERIF_A_SIGN)
            .write_value(CoefSign::Negative as u32);
        self.pka_write_field(RAM_VERIF_A, &P256_COEF_A_MAGNITUDE);
        self.pka_write_field(RAM_VERIF_MOD_P, &P);
        self.pka_write_field(RAM_VERIF_ORDER_N, &P256_ORDER);
        self.pka_write_field(RAM_VERIF_POINT_X, &P256_GX);
        self.pka_write_field(RAM_VERIF_POINT_Y, &P256_GY);
        self.pka_write_field(RAM_VERIF_PUBKEY_X, qx);
        self.pka_write_field(RAM_VERIF_PUBKEY_Y, qy);
        self.pka_write_field(RAM_VERIF_SIG_R, r);
        self.pka_write_field(RAM_VERIF_SIG_S, s);
        self.pka_write_field(RAM_VERIF_HASH_E, h);

        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(PKA_MODE_ECDSA_VERIFY);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        let sr = self.pka.sr().read();
        debug_assert!(
            !sr.addrerrf() && !sr.ramerrf(),
            "PKA ECDSA verify failed (SR error flags set)"
        );

        let valid = self.pka.ram(RAM_VERIF_OUT_RESULT).read() == PKA_NO_ERROR;

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        if valid {
            Ok(())
        } else {
            Err(embedded_cal::SignatureInvalid)
        }
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
