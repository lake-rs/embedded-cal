// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
use embedded_cal::{Cal, ImportError, SignProvider, SignatureInvalid, util::Either};
use p256::elliptic_curve::point::DecompressPoint;

use super::*;

impl<Base: Cal> SignProvider for RustcryptoCalExtender<Base> {
    type Algorithm = SignAlgorithm<SignAlgorithmOf<Base>>;
    type Signature = Signature<SignSignatureOf<Base>>;
    type SecretKey = SignSecretKey<SignSecretKeyOf<Base>>;
    type PublicKey = SignPublicKey<SignPublicKeyOf<Base>>;
    type VisibleSecretKey = SignVisibleSecretKey<SignVisibleSecretKeyOf<Base>>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                SignVisibleSecretKey::EcdsaP256(p256::ecdsa::SigningKey::random(&mut OldRng(self)))
            }
            SignAlgorithm::Direct(d) => {
                SignVisibleSecretKey::Direct(self.base.sign().generate_visible(d))
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, Base> {
        const MAX_SECRET_BYTES_LEN: usize = 32;
        match secretkey {
            SignVisibleSecretKey::EcdsaP256(signing_key) => {
                Either::Own(heapless::vec::Vec::<u8, MAX_SECRET_BYTES_LEN>::from(<[u8;
                    32]>::from(
                    signing_key.to_bytes(),
                )))
            }
            SignVisibleSecretKey::Direct(d) => {
                Either::Direct(self.base.sign().export_secretkey_bytes(d))
            }
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        Ok(match alg {
            SignAlgorithm::EcdsaP256 => SignVisibleSecretKey::EcdsaP256(
                p256::ecdsa::SigningKey::from_bytes(secret.into()).map_err(|_| ImportError)?,
            ),
            SignAlgorithm::Direct(d) => {
                SignVisibleSecretKey::Direct(self.base.sign().import_secretkey_bytes(d, secret)?)
            }
        })
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, Base> {
        match public {
            SignPublicKey::EcdsaP256(verifying_key) => Either::Own(
                *verifying_key
                    .to_encoded_point(false)
                    .x()
                    .expect("VerifyingKey can never be the identity point")
                    .as_array::<32>()
                    .expect("P-256 field elements are always 32 bytes"),
            ),
            SignPublicKey::Direct(d) => Either::Direct(self.base.sign().export_publickey_bytes(d)),
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => Ok(SignPublicKey::EcdsaP256(
                p256::ecdsa::VerifyingKey::from_affine(
                    p256::AffinePoint::decompress(
                        &<[u8; 32]>::try_from(data).map_err(|_| ImportError)?.into(),
                        // Using the trick from
                        // https://datatracker.ietf.org/doc/html/rfc9528#name-compact-representation,
                        // picking an arbitrary version for the compact import
                        0.into(),
                    )
                    .into_option()
                    .ok_or(ImportError)?,
                )
                .map_err(|_| ImportError)?,
            )),
            SignAlgorithm::Direct(d) => self
                .base
                .sign()
                .import_publickey_bytes(d, data)
                .map(SignPublicKey::Direct),
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SignSecretKey::EcdsaP256(signing_key) => {
                SignPublicKey::EcdsaP256(*signing_key.verifying_key())
            }
            SignSecretKey::Direct(d) => SignPublicKey::Direct(self.base.sign().public_key(d)),
        }
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, Base> {
        match signature {
            Signature::EcdsaP256(sig) => Either::Own(sig.to_bytes()),
            Signature::Direct(d) => Either::Direct(self.base.sign().export_signature_bytes(d)),
        }
    }

    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, embedded_cal::ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => Ok(Signature::EcdsaP256(
                #[allow(
                    clippy::unnecessary_fallible_conversions,
                    reason = "GenericArray has panicking From for slices"
                )]
                p256::ecdsa::Signature::from_bytes(data.try_into().map_err(|_| ImportError)?)
                    .map_err(|_| ImportError)?,
            )),
            SignAlgorithm::Direct(d) => self
                .base
                .sign()
                .import_signature_bytes(d, data)
                .map(Signature::Direct),
        }
    }

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        use p256::ecdsa::signature::Signer;
        match private {
            SignSecretKey::EcdsaP256(secret_key) => Signature::EcdsaP256(secret_key.sign(message)),
            SignSecretKey::Direct(secret_key) => {
                Signature::Direct(self.base.sign().sign(secret_key, message))
            }
        }
    }

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), embedded_cal::SignatureInvalid> {
        use p256::ecdsa::signature::Verifier;
        match (public, signature) {
            (SignPublicKey::EcdsaP256(public_key), Signature::EcdsaP256(sig)) => public_key
                .verify(message, sig)
                .map_err(|_| SignatureInvalid),
            (SignPublicKey::Direct(public_key), Signature::Direct(sig)) => {
                self.base.sign().verify(public_key, message, sig)
            }
            _ => Err(SignatureInvalid),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum SignAlgorithm<BA> {
    EcdsaP256,
    Direct(BA),
}

impl<BA: embedded_cal::SignAlgorithm> embedded_cal::SignAlgorithm for SignAlgorithm<BA> {
    fn signature_length(&self) -> usize {
        match self {
            SignAlgorithm::EcdsaP256 => 64,
            SignAlgorithm::Direct(base) => base.signature_length(),
        }
    }

    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        let alg: i128 = alg.into();
        if let Some(d) = BA::from_cose_number(alg) {
            return Some(SignAlgorithm::Direct(d));
        }
        Some(match alg {
            -7 => SignAlgorithm::EcdsaP256,
            _ => return None,
        })
    }
}

pub enum Signature<BSIG> {
    EcdsaP256(p256::ecdsa::Signature),
    Direct(BSIG),
}

pub enum SignSecretKey<BSK> {
    EcdsaP256(p256::ecdsa::SigningKey),
    Direct(BSK),
}

pub enum SignPublicKey<BPK> {
    EcdsaP256(p256::ecdsa::VerifyingKey),
    Direct(BPK),
}

pub enum SignVisibleSecretKey<BVSK> {
    EcdsaP256(p256::ecdsa::SigningKey),
    Direct(BVSK),
}

impl<BVSK, BSK> From<SignVisibleSecretKey<BVSK>> for SignSecretKey<BSK>
where
    BVSK: Into<BSK>,
{
    fn from(value: SignVisibleSecretKey<BVSK>) -> Self {
        match value {
            SignVisibleSecretKey::EcdsaP256(signing_key) => SignSecretKey::EcdsaP256(signing_key),
            SignVisibleSecretKey::Direct(d) => SignSecretKey::Direct(d.into()),
        }
    }
}

struct OldRng<'c, C: embedded_cal::Cal>(&'c mut C);

impl<'c, C: embedded_cal::Cal + rand_core::CryptoRng> rand_core_06::CryptoRng for OldRng<'c, C> {}
impl<'c, C: embedded_cal::Cal + rand_core::CryptoRng> rand_core_06::RngCore for OldRng<'c, C> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}
