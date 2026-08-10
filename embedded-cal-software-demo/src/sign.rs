// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{
    HashProvider, ImportError, SignatureInvalid,
    p256::{P256_GX_BYTES, P256_GY_BYTES, P256_ORDER, bytes_to_words, ge},
    plumbing::ecdsa::EcdsaP256,
};
use rand_core::Rng as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Extender, ExtenderConfig};
use crate::hash::HashAlgorithm;

#[derive(PartialEq, Eq, Debug, Clone, Zeroize, Copy)]
pub enum Algorithm {
    EcdsaP256,
}

impl embedded_cal::SignAlgorithm for Algorithm {
    fn signature_length(&self) -> usize {
        match self {
            Algorithm::EcdsaP256 => 64,
        }
    }

    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        match alg.into() {
            -7 => Some(Algorithm::EcdsaP256),
            _ => None,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    alg: Algorithm,
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
    // Unread while `Algorithm` has a single variant; kept for when a second signature
    // algorithm is added and callers need to distinguish keys/signatures by algorithm.
    #[allow(dead_code)]
    alg: Algorithm,
    x: [u8; 32],
    y: [u8; 32],
}

pub struct Signature {
    #[allow(dead_code)]
    alg: Algorithm,
    r: [u8; 32],
    s: [u8; 32],
}

impl<EC: ExtenderConfig> embedded_cal::SignProvider for Extender<EC>
where
    EC::Base: EcdsaP256 + rand_core::TryRng<Error = core::convert::Infallible>,
{
    type Algorithm = Algorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            Algorithm::EcdsaP256 => loop {
                let mut scalar = [0u8; 32];
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
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        &secretkey.0.scalar[..]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        match alg {
            Algorithm::EcdsaP256 => {
                let scalar = secret.try_into().map_err(|_| ImportError)?;
                Ok(VisibleSecretKey(SecretKey { alg, scalar }))
            }
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        &public.x[..]
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, ImportError> {
        match alg {
            Algorithm::EcdsaP256 => {
                let x: [u8; 32] = data.try_into().map_err(|_| ImportError)?;
                let y = embedded_cal::p256::p256_recover_y(&x)?;
                Ok(PublicKey { alg, x, y })
            }
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let (x, y) = self
            .0
            .p256_mult(&private.scalar, &P256_GX_BYTES, &P256_GY_BYTES);
        PublicKey {
            alg: private.alg,
            x,
            y,
        }
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&signature.r);
        bytes[32..].copy_from_slice(&signature.s);
        bytes
    }

    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, ImportError> {
        match alg {
            Algorithm::EcdsaP256 => {
                if data.len() != 64 {
                    return Err(ImportError);
                }
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&data[..32]);
                s.copy_from_slice(&data[32..]);
                Ok(Signature { alg, r, s })
            }
        }
    }

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        let digest: [u8; 32] = self
            .hash(HashAlgorithm::Sha256, message)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is always 32 bytes");

        loop {
            let mut k_bytes = [0u8; 32];
            loop {
                self.fill_bytes(&mut k_bytes);
                let kw = bytes_to_words(&k_bytes);
                if kw != [0u32; 8] && !ge(&kw, &P256_ORDER) {
                    break;
                }
            }

            if let Some((r, s)) = self.0.ecdsa_sign(&private.scalar, &k_bytes, &digest) {
                return Signature {
                    alg: private.alg,
                    r,
                    s,
                };
            }
        }
    }

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid> {
        let r = bytes_to_words(&signature.r);
        let s = bytes_to_words(&signature.s);
        if r == [0u32; 8] || ge(&r, &P256_ORDER) || s == [0u32; 8] || ge(&s, &P256_ORDER) {
            return Err(SignatureInvalid);
        }

        let digest: [u8; 32] = self
            .hash(HashAlgorithm::Sha256, message)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is always 32 bytes");

        self.0
            .ecdsa_verify(&public.x, &public.y, &digest, &signature.r, &signature.s)
    }
}
