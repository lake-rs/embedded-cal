// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
use embedded_cal::{Cal, ImportError, SignProvider, SignatureInvalid, util::Either};

use super::*;

impl<Base> SignProvider for RustcryptoCalExtender<Base>
where
    Base: Cal + rand_core::TryCryptoRng<Error = core::convert::Infallible>,
{
    type Algorithm = SignAlgorithm<SignAlgorithmOf<Base>>;
    type Signature = Signature<SignSignatureOf<Base>>;
    type SecretKey = SignSecretKey<SignSecretKeyOf<Base>>;
    type PublicKey = SignPublicKey<SignPublicKeyOf<Base>>;
    type VisibleSecretKey = SignVisibleSecretKey<SignVisibleSecretKeyOf<Base>>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        use p256::elliptic_curve::Generate;
        match alg {
            SignAlgorithm::EcdsaP256 => {
                SignVisibleSecretKey::EcdsaP256(p256::ecdsa::SigningKey::generate_from_rng(self))
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
                p256::ecdsa::SigningKey::from_bytes(secret.try_into().map_err(|_| ImportError)?)
                    .map_err(|_| ImportError)?,
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
            // SEC1 compressed form: 0x02 or 0x03 (parity of y), followed by x
            SignPublicKey::EcdsaP256(verifying_key) => Either::Own(
                <[u8; 33]>::try_from(verifying_key.to_sec1_point(true).as_bytes())
                    .expect("compressed P-256 points are always 33 bytes"),
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
            // Unlike for ECDH, the parity of y matters for ECDSA, so only the SEC1 compressed form
            // produced by export_publickey_bytes is accepted.
            SignAlgorithm::EcdsaP256 if data.len() != 33 => Err(ImportError),
            SignAlgorithm::EcdsaP256 => Ok(SignPublicKey::EcdsaP256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(data).map_err(|_| ImportError)?,
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
