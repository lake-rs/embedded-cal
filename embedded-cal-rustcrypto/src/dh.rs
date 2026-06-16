// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::RustcryptoCal;
use embedded_cal::ImportError;
use zeroize::{Zeroize, ZeroizeOnDrop};

impl embedded_cal::DhProvider for RustcryptoCal {
    type Algorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        // We're not wrapping anything, so no point in deferring to the self RNG.
        VisibleSecretKey(match alg {
            DhAlgorithm::P256 => SecretKey::P256(p256::SecretKey::random(&mut OldRng(self))),
            DhAlgorithm::X25519 => {
                SecretKey::X25519(x25519_dalek::StaticSecret::random_from_rng(OldRng(self)))
            }
        })
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secret: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        const MAX_SECRET_BYTES_LEN: usize = 32;
        let secret_bytes: heapless::vec::Vec<u8, MAX_SECRET_BYTES_LEN> = match &secret.0 {
            SecretKey::P256(secret_key) => <[u8; 32]>::from(secret_key.to_bytes()).into(),
            SecretKey::X25519(secret_key) => secret_key.to_bytes().into(),
        };
        secret_bytes
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        Ok(VisibleSecretKey(match alg {
            DhAlgorithm::P256 => SecretKey::P256(
                #[allow(
                    clippy::unnecessary_fallible_conversions,
                    reason = "GenericArray has panicking From for slices"
                )]
                p256::SecretKey::from_bytes(secret.try_into().map_err(|_| ImportError)?)
                    .map_err(|_| ImportError)?,
            ),
            // It's one of the nice aspects of x25519 that all values of [u8; 32] are valid curve
            // points, so the only fallible point is the key length.
            DhAlgorithm::X25519 => SecretKey::X25519(x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(secret).map_err(|_| ImportError)?,
            )),
        }))
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        Ok(SharedSecret(match (private, public) {
            (SecretKey::P256(secret_key), PublicKey::P256(public_key)) => {
                p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine())
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()
                    .expect("MAX_SHARED_SECRET_LENGTH is long enough")
            }
            (SecretKey::X25519(secret_key), PublicKey::X25519(public_key)) => {
                secret_key.diffie_hellman(public_key).to_bytes().into()
            }
            _ => return Err(embedded_cal::IncompatibleKeys),
        }))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::P256(secret_key) => PublicKey::P256(secret_key.public_key()),
            SecretKey::X25519(secret_key) => PublicKey::X25519(secret_key.into()),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secret.0
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        match public {
            PublicKey::P256(public_key) => *public_key
                .to_encoded_point(false)
                .x()
                .unwrap()
                .as_array()
                .unwrap(),
            // FIXME: If we're only supporting X25519, we could do without the dereferencing and
            // shove less data around.
            PublicKey::X25519(public_key) => *public_key.as_bytes(),
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, ImportError> {
        use p256::elliptic_curve::point::DecompressPoint;
        match alg {
            DhAlgorithm::P256 => Ok(PublicKey::P256(
                p256::PublicKey::from_affine(
                    p256::AffinePoint::decompress(
                        &<[u8; 32]>::try_from(data).map_err(|_| ImportError)?.into(),
                        // Using the trick from
                        // https://datatracker.ietf.org/doc/html/rfc9528#name-compact-representation,
                        // picking an arbitrary version for the compact import
                        0.into(),
                    )
                    // FIXME Should we try to stay subtle?
                    .into_option()
                    .ok_or(ImportError)?,
                )
                .map_err(|_| ImportError)?,
            )),
            DhAlgorithm::X25519 => Ok(PublicKey::X25519(x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(data).map_err(|_| ImportError)?,
            ))),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DhAlgorithm {
    P256,
    X25519,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::P256 => 32,
            DhAlgorithm::X25519 => 32,
        }
    }

    #[inline]
    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        Some(match curve.into() {
            1 => DhAlgorithm::P256,
            4 => DhAlgorithm::X25519,
            _ => return None,
        })
    }
}

pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(value: VisibleSecretKey) -> Self {
        value.0
    }
}

pub enum SecretKey {
    P256(p256::SecretKey),
    // FIXME: x25519_dalek differentiates between StaticSecret and ReusableSecret, could do that here
    // too (probably we'd have a ReusableSecret here but a StaticSecret in VisibleSecretKey)
    X25519(x25519_dalek::StaticSecret),
}

pub enum PublicKey {
    P256(p256::PublicKey),
    X25519(x25519_dalek::PublicKey),
}

const MAX_SHARED_SECRET_LENGTH: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(heapless::Vec<u8, MAX_SHARED_SECRET_LENGTH>);

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
