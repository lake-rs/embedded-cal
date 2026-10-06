// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! ECDSA on P-256, hashing in software and leaving the curve operations to the
//! [`Ecdsa`][embedded_cal::plumbing::ecdsa::Ecdsa] and [`Ec`] plumbing of the base.

use embedded_cal::{
    Cal, HashProvider, ImportError, SignProvider, SignatureInvalid,
    accessor::*,
    plumbing::{
        ec::{Ec, EcPrimitives, P256},
        ecdsa::Ecdsa,
    },
    util::p256::{
        P256_GX_BYTES, P256_GY_BYTES, P256_ORDER, bytes_to_words, ge, p256_recover_y_with_parity,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Extender, ExtenderConfig};
use crate::hash::HashAlgorithm;

/// Private scalar of an ECDSA P-256 key, big-endian.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateScalar([u8; 32]);

pub enum SignAlgorithm<EC: ExtenderConfig> {
    EcdsaP256,
    Direct(SignAlgorithmOf<EC::Base>),
}

// Derives would require EC itself to implement these; see HashAlgorithm.
impl<EC: ExtenderConfig> Clone for SignAlgorithm<EC> {
    fn clone(&self) -> Self {
        match self {
            SignAlgorithm::EcdsaP256 => SignAlgorithm::EcdsaP256,
            SignAlgorithm::Direct(a) => SignAlgorithm::Direct(a.clone()),
        }
    }
}

impl<EC: ExtenderConfig> core::fmt::Debug for SignAlgorithm<EC> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignAlgorithm::EcdsaP256 => write!(f, "EcdsaP256"),
            SignAlgorithm::Direct(arg0) => f.debug_tuple("Direct").field(arg0).finish(),
        }
    }
}

impl<EC: ExtenderConfig> PartialEq for SignAlgorithm<EC> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SignAlgorithm::EcdsaP256, SignAlgorithm::EcdsaP256) => true,
            (SignAlgorithm::Direct(a), SignAlgorithm::Direct(b)) => a == b,
            _ => false,
        }
    }
}

impl<EC: ExtenderConfig> Eq for SignAlgorithm<EC> {}

impl<EC: ExtenderConfig> embedded_cal::SignAlgorithm for SignAlgorithm<EC> {
    fn signature_length(&self) -> usize {
        match self {
            SignAlgorithm::EcdsaP256 => 64,
            SignAlgorithm::Direct(a) => a.signature_length(),
        }
    }

    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        let alg: i128 = alg.into();

        // Signing needs the SHA-256 implemented here, the base's ECDSA plumbing, and its P-256
        // point multiplication to derive public keys.
        let supported = EC::IMPLEMENT_SHA2SHORT
            && <EC::Base as Ecdsa>::SUPPORTED
            && <<EC::Base as Ec>::PrimitivesP256 as EcPrimitives<P256>>::HAS_MULTIPLY_SCALAR_POINT;

        match alg {
            -7 if supported => Some(SignAlgorithm::EcdsaP256),
            _ => SignAlgorithmOf::<EC::Base>::from_cose_number(alg).map(SignAlgorithm::Direct),
        }
    }
}

pub enum SecretKey<EC: ExtenderConfig> {
    EcdsaP256(PrivateScalar),
    Direct(SignSecretKeyOf<EC::Base>),
}

pub enum VisibleSecretKey<EC: ExtenderConfig> {
    EcdsaP256(PrivateScalar),
    Direct(SignVisibleSecretKeyOf<EC::Base>),
}

impl<EC: ExtenderConfig> From<VisibleSecretKey<EC>> for SecretKey<EC> {
    fn from(value: VisibleSecretKey<EC>) -> Self {
        match value {
            VisibleSecretKey::EcdsaP256(d) => SecretKey::EcdsaP256(d),
            VisibleSecretKey::Direct(d) => SecretKey::Direct(d.into()),
        }
    }
}

pub enum PublicKey<EC: ExtenderConfig> {
    EcdsaP256 { x: [u8; 32], y: [u8; 32] },
    Direct(SignPublicKeyOf<EC::Base>),
}

pub enum Signature<EC: ExtenderConfig> {
    EcdsaP256 { r: [u8; 32], s: [u8; 32] },
    Direct(SignSignatureOf<EC::Base>),
}

/// Whether `w` is in `1..n`, as needed for private scalars and signature components.
fn in_scalar_range(w: &[u8; 32]) -> bool {
    let w = bytes_to_words(w);
    w != [0u32; 8] && !ge(&w, &P256_ORDER)
}

impl<EC: ExtenderConfig> Extender<EC> {
    fn sha256(&mut self, message: &[u8]) -> [u8; 32] {
        HashProvider::hash(self, HashAlgorithm::Sha256, message)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is always 32 bytes")
    }
}

impl<EC: ExtenderConfig> SignProvider for Extender<EC> {
    type Algorithm = SignAlgorithm<EC>;
    type VisibleSecretKey = VisibleSecretKey<EC>;
    type SecretKey = SecretKey<EC>;
    type PublicKey = PublicKey<EC>;
    type Signature = Signature<EC>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                VisibleSecretKey::EcdsaP256(PrivateScalar(self.0.ecdsa_p256_generate()))
            }
            SignAlgorithm::Direct(a) => VisibleSecretKey::Direct(self.0.sign().generate_visible(a)),
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        match secretkey {
            VisibleSecretKey::EcdsaP256(d) => embedded_cal::util::Either::Own(&d.0[..]),
            VisibleSecretKey::Direct(d) => {
                embedded_cal::util::Either::Direct(self.0.sign().export_secretkey_bytes(d))
            }
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                let d = PrivateScalar(secret.try_into().map_err(|_| ImportError)?);
                if !in_scalar_range(&d.0) {
                    return Err(ImportError);
                }
                Ok(VisibleSecretKey::EcdsaP256(d))
            }
            SignAlgorithm::Direct(a) => self
                .0
                .sign()
                .import_secretkey_bytes(a, secret)
                .map(VisibleSecretKey::Direct),
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        match public {
            // SEC1 compressed form: 0x02 or 0x03 (parity of y), followed by x
            PublicKey::EcdsaP256 { x, y } => {
                let mut compressed = [0u8; 33];
                compressed[0] = 0x02 | (y[31] & 1);
                compressed[1..].copy_from_slice(x);
                embedded_cal::util::Either::Own(compressed)
            }
            PublicKey::Direct(p) => {
                embedded_cal::util::Either::Direct(self.0.sign().export_publickey_bytes(p))
            }
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, ImportError> {
        match alg {
            // Unlike for ECDH, the parity of y matters for ECDSA, so only the SEC1 compressed form
            // produced by export_publickey_bytes is accepted.
            SignAlgorithm::EcdsaP256 => {
                let (&prefix, x) = data.split_first().ok_or(ImportError)?;
                let x: [u8; 32] = x.try_into().map_err(|_| ImportError)?;
                let odd = match prefix {
                    0x02 => false,
                    0x03 => true,
                    _ => return Err(ImportError),
                };
                let y = p256_recover_y_with_parity(&x, odd)?;
                Ok(PublicKey::EcdsaP256 { x, y })
            }
            SignAlgorithm::Direct(a) => self
                .0
                .sign()
                .import_publickey_bytes(a, data)
                .map(PublicKey::Direct),
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::EcdsaP256(d) => {
                let p256 = self.0.p256();
                let gx = p256
                    .import_scalar_bytes(&P256_GX_BYTES)
                    .expect("generator x is a valid scalar");
                let gy = p256
                    .import_scalar_bytes(&P256_GY_BYTES)
                    .expect("generator y is a valid scalar");
                let generator = p256.point(gx, gy);
                let d = p256
                    .import_scalar_bytes(&d.0)
                    .expect("private scalar was range checked on import");
                let q = p256.multiply_scalar_point(&d, &generator);

                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                let qx = p256.x_coord(&q);
                x.copy_from_slice(p256.export_scalar_bytes(&qx).as_ref());
                let qy = p256.y_coord(&q);
                y.copy_from_slice(p256.export_scalar_bytes(&qy).as_ref());
                PublicKey::EcdsaP256 { x, y }
            }
            SecretKey::Direct(d) => PublicKey::Direct(self.0.sign().public_key(d)),
        }
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        match signature {
            Signature::EcdsaP256 { r, s } => {
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(r);
                bytes[32..].copy_from_slice(s);
                embedded_cal::util::Either::Own(bytes)
            }
            Signature::Direct(s) => {
                embedded_cal::util::Either::Direct(self.0.sign().export_signature_bytes(s))
            }
        }
    }

    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, ImportError> {
        match alg {
            SignAlgorithm::EcdsaP256 => {
                let data: &[u8; 64] = data.try_into().map_err(|_| ImportError)?;
                let (r, s) = data.split_at(32);
                Ok(Signature::EcdsaP256 {
                    r: r.try_into().expect("split at 32 of 64"),
                    s: s.try_into().expect("split at 32 of 64"),
                })
            }
            SignAlgorithm::Direct(a) => self
                .0
                .sign()
                .import_signature_bytes(a, data)
                .map(Signature::Direct),
        }
    }

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        match private {
            SecretKey::EcdsaP256(d) => {
                let digest = self.sha256(message);
                let (r, s) = self.0.ecdsa_p256_sign(&d.0, &digest);
                Signature::EcdsaP256 { r, s }
            }
            SecretKey::Direct(d) => Signature::Direct(self.0.sign().sign(d, message)),
        }
    }

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid> {
        match (public, signature) {
            (PublicKey::EcdsaP256 { x, y }, Signature::EcdsaP256 { r, s }) => {
                if !in_scalar_range(r) || !in_scalar_range(s) {
                    return Err(SignatureInvalid);
                }
                let digest = self.sha256(message);
                self.0.ecdsa_p256_verify(x, y, &digest, r, s)
            }
            (PublicKey::Direct(p), Signature::Direct(s)) => self.0.sign().verify(p, message, s),
            _ => Err(SignatureInvalid),
        }
    }
}
