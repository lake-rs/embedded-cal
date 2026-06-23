// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::*;
use embedded_cal::{Cal, DhProvider, ImportError, util::Either};

impl<Base: Cal> DhProvider for RustcryptoCalExtender<Base> {
    type Algorithm = DhAlgorithm<DhAlgorithmOf<Base>>;
    type VisibleSecretKey = VisibleSecretKey<DhVisibleSecretKeyOf<Base>>;
    type SecretKey = SecretKey<DhSecretKeyOf<Base>>;
    type PublicKey = PublicKey<DhPublicKeyOf<Base>>;
    type SharedSecret = SharedSecret<DhSharedSecretOf<Base>>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        // We're not wrapping anything, so no point in deferring to the self RNG.
        match alg {
            DhAlgorithm::P256 => VisibleSecretKey::P256(p256::SecretKey::random(&mut OldRng(self))),
            DhAlgorithm::X25519 => {
                VisibleSecretKey::X25519(x25519_dalek::StaticSecret::random_from_rng(OldRng(self)))
            }
            DhAlgorithm::Direct(d) => VisibleSecretKey::Direct(self.base.dh().generate_visible(d)),
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secret: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, Base> {
        const MAX_SECRET_BYTES_LEN: usize = 32;
        match secret {
            VisibleSecretKey::P256(secret_key) => {
                Either::Own(heapless::vec::Vec::<u8, MAX_SECRET_BYTES_LEN>::from(<[u8;
                    32]>::from(
                    secret_key.to_bytes(),
                )))
            }
            VisibleSecretKey::X25519(secret_key) => Either::Own(secret_key.to_bytes().into()),
            VisibleSecretKey::Direct(d) => Either::Direct(self.base.dh().export_secretkey_bytes(d)),
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        Ok(match alg {
            DhAlgorithm::P256 => VisibleSecretKey::P256(
                #[allow(
                    clippy::unnecessary_fallible_conversions,
                    reason = "GenericArray has panicking From for slices"
                )]
                p256::SecretKey::from_bytes(secret.try_into().map_err(|_| ImportError)?)
                    .map_err(|_| ImportError)?,
            ),
            // It's one of the nice aspects of x25519 that all values of [u8; 32] are valid curve
            // points, so the only fallible point is the key length.
            DhAlgorithm::X25519 => VisibleSecretKey::X25519(x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(secret).map_err(|_| ImportError)?,
            )),
            DhAlgorithm::Direct(d) => {
                VisibleSecretKey::Direct(self.base.dh().import_secretkey_bytes(d, secret)?)
            }
        })
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        Ok(match (private, public) {
            (SecretKey::P256(secret_key), PublicKey::P256(public_key)) => SharedSecret::Length32(
                (*p256::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                )
                .raw_secret_bytes())
                .into(),
            ),
            (SecretKey::X25519(secret_key), PublicKey::X25519(public_key)) => {
                SharedSecret::Length32(secret_key.diffie_hellman(public_key).to_bytes().into())
            }
            (SecretKey::Direct(secret_key), PublicKey::Direct(public_key)) => {
                SharedSecret::Direct(self.base.dh().shared_secret(secret_key, public_key)?)
            }
            _ => return Err(embedded_cal::IncompatibleKeys),
        })
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::P256(secret_key) => PublicKey::P256(secret_key.public_key()),
            SecretKey::X25519(secret_key) => PublicKey::X25519(secret_key.into()),
            SecretKey::Direct(d) => PublicKey::Direct(self.base.dh().public_key(d)),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, Base> {
        match &secret {
            SharedSecret::Length32(inner) => Either::Own(inner),
            SharedSecret::Direct(d) => Either::Direct(self.base.dh().raw_secret_bytes(d)),
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, Base> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        match public {
            PublicKey::P256(public_key) => Either::Own(
                *public_key
                    .to_encoded_point(false)
                    .x()
                    .unwrap()
                    .as_array()
                    .unwrap(),
            ),
            // FIXME: If we're only supporting X25519, we could do without the dereferencing and
            // shove less data around.
            PublicKey::X25519(public_key) => Either::Own(*public_key.as_bytes()),
            PublicKey::Direct(d) => Either::Direct(self.base.dh().export_publickey_bytes(d)),
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
            DhAlgorithm::Direct(d) => self
                .base
                .dh()
                .import_publickey_bytes(d, data)
                .map(PublicKey::Direct),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DhAlgorithm<BA> {
    P256,
    X25519,
    Direct(BA),
}

impl<BA: embedded_cal::DhAlgorithm> embedded_cal::DhAlgorithm for DhAlgorithm<BA> {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::P256 => 32,
            DhAlgorithm::X25519 => 32,
            DhAlgorithm::Direct(d) => d.output_length(),
        }
    }

    #[inline]
    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        let curve: i128 = curve.into();
        if let Some(d) = BA::from_cose_ecdh(curve) {
            return Some(DhAlgorithm::Direct(d));
        };
        Some(match curve {
            1 => DhAlgorithm::P256,
            4 => DhAlgorithm::X25519,
            _ => return None,
        })
    }
}

pub enum VisibleSecretKey<BVSK> {
    P256(p256::SecretKey),
    X25519(x25519_dalek::StaticSecret),
    Direct(BVSK),
}

impl<BVSK, BSK> From<VisibleSecretKey<BVSK>> for SecretKey<BSK>
where
    BVSK: Into<BSK>,
{
    fn from(value: VisibleSecretKey<BVSK>) -> Self {
        match value {
            VisibleSecretKey::P256(k) => SecretKey::P256(k),
            VisibleSecretKey::X25519(k) => SecretKey::X25519(k),
            VisibleSecretKey::Direct(d) => SecretKey::Direct(d.into()),
        }
    }
}

pub enum SecretKey<BSK> {
    P256(p256::SecretKey),
    // FIXME: x25519_dalek differentiates between StaticSecret and ReusableSecret, could do that here
    // too (probably we'd have a ReusableSecret here but a StaticSecret in VisibleSecretKey)
    X25519(x25519_dalek::StaticSecret),
    Direct(BSK),
}

pub enum PublicKey<BPK> {
    P256(p256::PublicKey),
    X25519(x25519_dalek::PublicKey),
    Direct(BPK),
}

pub enum SharedSecret<BSS> {
    Length32([u8; 32]),
    Direct(BSS),
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
