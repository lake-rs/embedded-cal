// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! ECDSA on P-256 with SHA-256 (COSE "ES256"), using the HASH engine for the digest and the PKA
//! for point and scalar arithmetic (see [`crate::ec`]).
//!
//! Formats follow the other embedded-cal implementations: the secret key is the big-endian `d`,
//! public keys are exported in SEC1 compressed form, signatures as raw `r || s`.

use crate::ec::sub_words;
use crate::{Nrf5340Cal, ct};
use embedded_cal::util::p256::{
    P, P256_GX_BYTES, P256_GY_BYTES, bytes_to_words, p256_recover_y, words_to_bytes,
};
use embedded_cal::{ImportError, SignatureInvalid};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum SignAlgorithm {
    EcdsaP256,
}

impl embedded_cal::SignAlgorithm for SignAlgorithm {
    fn signature_length(&self) -> usize {
        match self {
            SignAlgorithm::EcdsaP256 => 64,
        }
    }

    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        match alg.into() {
            -7 => Some(SignAlgorithm::EcdsaP256),
            _ => None,
        }
    }
}

/// It is an invariant of this type that the scalar is in `1..n`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SecretKey {
    EcdsaP256([u8; 32]),
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

/// It is an invariant of this type that the point is on the curve.
pub enum PublicKey {
    EcdsaP256 {
        x: [u8; 32],
        y: [u8; 32],
        /// SEC1 compressed encoding, kept for export.
        compressed: [u8; 33],
    },
}

pub enum Signature {
    /// Raw `r || s`
    EcdsaP256([u8; 64]),
}

/// Whether a big-endian scalar is in `1..n`.
///
/// Computed in constant time; only the final answer, which becomes public as the outcome of the
/// import or the verification, is branched on.
fn is_valid_scalar(s: &[u8; 32]) -> bool {
    ct::p256_scalar_valid_mask(s) == 0xFF
}

/// Reduces a 256-bit big-endian number (a digest or a field element) mod n, in constant time.
fn reduce_mod_n(v: &[u8; 32]) -> [u8; 32] {
    ct::p256_reduce_once(v)
}

fn public_key_from_coordinates(x: [u8; 32], y: [u8; 32]) -> PublicKey {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (y[31] & 1);
    compressed[1..].copy_from_slice(&x);
    PublicKey::EcdsaP256 { x, y, compressed }
}

impl embedded_cal::SignProvider for Nrf5340Cal {
    type Algorithm = SignAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            // No rejection loop on the secret candidate; see `p256_random_scalar`.
            SignAlgorithm::EcdsaP256 => {
                VisibleSecretKey(SecretKey::EcdsaP256(self.p256_random_scalar()))
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        match &secretkey.0 {
            SecretKey::EcdsaP256(d) => d.as_slice(),
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                let d: [u8; 32] = secret.try_into().map_err(|_| ImportError)?;
                if !is_valid_scalar(&d) {
                    return Err(ImportError);
                }
                Ok(VisibleSecretKey(SecretKey::EcdsaP256(d)))
            }
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        match public {
            PublicKey::EcdsaP256 { compressed, .. } => compressed.as_slice(),
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                // Only the SEC1 compressed form produced by export_publickey_bytes is accepted.
                let data: &[u8; 33] = data.try_into().map_err(|_| ImportError)?;
                let parity = match data[0] {
                    0x02 => 0,
                    0x03 => 1,
                    _ => return Err(ImportError),
                };
                let x: [u8; 32] = data[1..].try_into().expect("length checked");
                // Fails for x >= p and for x not on the curve.
                let mut y = p256_recover_y(&x)?;
                if y[31] & 1 != parity {
                    // y != 0, as P-256 has no point of order 2.
                    let mut negated = P;
                    sub_words(&mut negated, &bytes_to_words(&y));
                    y = words_to_bytes(&negated);
                }
                Ok(public_key_from_coordinates(x, y))
            }
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::EcdsaP256(d) => {
                let (x, y) = self.p256_mul(d, &P256_GX_BYTES, &P256_GY_BYTES);
                public_key_from_coordinates(x, y)
            }
        }
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s> {
        match signature {
            Signature::EcdsaP256(rs) => rs.as_slice(),
        }
    }

    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                let rs: [u8; 64] = data.try_into().map_err(|_| ImportError)?;
                let (r, s) = rs.split_at(32);
                if !is_valid_scalar(r.try_into().expect("split at 32"))
                    || !is_valid_scalar(s.try_into().expect("split at 32"))
                {
                    return Err(ImportError);
                }
                Ok(Signature::EcdsaP256(rs))
            }
        }
    }

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        let SecretKey::EcdsaP256(d) = private;
        let e = reduce_mod_n(&self.sha256(&[message]));

        // FIPS 186-5 6.4.1 with a random per-message secret k from the TRNG. The only retries are
        // on r = 0 or s = 0, which are public (they would be the signature).
        loop {
            let mut k = self.p256_random_scalar();

            let (x, _) = self.p256_mul(&k, &P256_GX_BYTES, &P256_GY_BYTES);
            let r = reduce_mod_n(&x);
            if r == [0; 32] {
                k.zeroize();
                continue;
            }

            let s = {
                let ops = self.p256_scalar_ops();
                let mut k_inv = ops.inv(&k);
                let s = ops.mul_add_mul(&k_inv, &e, &r, d);
                k_inv.zeroize();
                s
            };
            k.zeroize();
            if s == [0; 32] {
                continue;
            }

            let mut rs = [0u8; 64];
            rs[..32].copy_from_slice(&r);
            rs[32..].copy_from_slice(&s);
            return Signature::EcdsaP256(rs);
        }
    }

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid> {
        let (PublicKey::EcdsaP256 { x: qx, y: qy, .. }, Signature::EcdsaP256(rs)) =
            (public, signature);
        let r: [u8; 32] = rs[..32].try_into().expect("split at 32");
        let s: [u8; 32] = rs[32..].try_into().expect("split at 32");
        if !is_valid_scalar(&r) || !is_valid_scalar(&s) {
            return Err(SignatureInvalid);
        }

        let e = reduce_mod_n(&self.sha256(&[message]));

        // FIPS 186-5 6.4.2
        let (u1, u2) = {
            let ops = self.p256_scalar_ops();
            let w = ops.inv(&s);
            (ops.mul(&e, &w), ops.mul(&r, &w))
        };
        let x = self
            .p256_mul_add(&u1, &u2, qx, qy)
            .ok_or(SignatureInvalid)?;

        if reduce_mod_n(&x) == r {
            Ok(())
        } else {
            Err(SignatureInvalid)
        }
    }
}
