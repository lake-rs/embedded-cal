// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{
    Cal, DhProvider,
    accessor::{
        DhAlgorithmOf, DhPublicKeyOf, DhSecretKeyOf, DhSharedSecretOf, DhVisibleSecretKeyOf,
    },
    util::Either,
};
use libcrux_iot_p256::{
    P256, compressed_to_raw,
    ecdh_api::{EcdhOwned, PUBLIC_LEN, SECRET_LEN},
};
use libcrux_secrets::{ClassifyRef, DeclassifyRef, U8};
use rand_core::Rng;

use crate::{Extender, ExtenderConfig};

// Length of the p256 ecdh shared secret. Currently not exposed by libcrux.
const P256_SHARED_SECRET_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DhAlgorithm<BA> {
    P256,
    Direct(BA),
}

impl<Base: embedded_cal::DhAlgorithm> embedded_cal::DhAlgorithm for DhAlgorithm<Base> {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::P256 => P256_SHARED_SECRET_LEN,
            DhAlgorithm::Direct(d) => d.output_length(),
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        let curve: i128 = curve.into();
        if let Some(base_algo) = Base::from_cose_ecdh(curve) {
            return Some(DhAlgorithm::Direct(base_algo));
        };
        Some(match curve {
            1 => DhAlgorithm::P256,
            _ => return None,
        })
    }
}

// We don't want to provide mutable access to the key bytes, so create this
// new-type that can be put into the pub enum
pub struct P256SecretKey([U8; SECRET_LEN]);

pub enum VisibleSecretKey<BVSK> {
    P256(P256SecretKey),
    Direct(BVSK),
}

pub enum SecretKey<BSK> {
    P256(P256SecretKey),
    Direct(BSK),
}

// Also don't expose the public key bytes directly
pub struct P256PublicKey([u8; PUBLIC_LEN]);

impl P256PublicKey {
    fn x(&self) -> &[u8; 32] {
        const { assert!(PUBLIC_LEN == 64) };
        self.0.first_chunk().expect("slice has len 64")
    }
}

pub enum PublicKey<BPK> {
    P256(P256PublicKey),
    Direct(BPK),
}

pub enum SharedSecret<BSS> {
    P256([U8; P256_SHARED_SECRET_LEN]),
    Direct(BSS),
}

impl<EC: ExtenderConfig> DhProvider for Extender<EC> {
    type Algorithm = DhAlgorithm<DhAlgorithmOf<EC::Base>>;

    type VisibleSecretKey = VisibleSecretKey<DhVisibleSecretKeyOf<EC::Base>>;

    type SecretKey = SecretKey<DhSecretKeyOf<EC::Base>>;

    type PublicKey = PublicKey<DhPublicKeyOf<EC::Base>>;

    type SharedSecret = SharedSecret<DhSharedSecretOf<EC::Base>>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            DhAlgorithm::P256 => {
                let mut rand = [0; _];
                // libcrux p256 does not perform rejection sampling or sampling with extra bits.
                // It only checks whether the provided random value would be a valid key or not,
                // so we implement a simple rejection sampling here.
                loop {
                    self.fill_bytes(&mut rand);
                    if let Ok(secret) = P256::generate_secret(rand.classify_ref()) {
                        return VisibleSecretKey::P256(P256SecretKey(secret));
                    }
                }
            }
            DhAlgorithm::Direct(d) => VisibleSecretKey::Direct(self.0.dh().generate_visible(d)),
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        match secretkey {
            VisibleSecretKey::P256(secret) => Either::Own(secret.0.declassify_ref()),
            VisibleSecretKey::Direct(d) => Either::Direct(self.0.dh().export_secretkey_bytes(d)),
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        match alg {
            DhAlgorithm::P256 => {
                let secret = secret
                    .classify_ref()
                    .try_into()
                    .map_err(|_| embedded_cal::ImportError)?;
                P256::validate_secret(secret).map_err(|_| embedded_cal::ImportError)?;
                Ok(VisibleSecretKey::P256(P256SecretKey(*secret)))
            }
            DhAlgorithm::Direct(base_algo) => self
                .0
                .dh()
                .import_secretkey_bytes(base_algo, secret)
                .map(VisibleSecretKey::Direct),
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        match public {
            // Return compact encoding of pk, i.e. just the x coordinate
            PublicKey::P256(pk_bytes) => Either::Own(pk_bytes.x()),
            PublicKey::Direct(pk_bytes) => {
                Either::Direct(self.0.dh().export_publickey_bytes(pk_bytes))
            }
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        match alg {
            DhAlgorithm::P256 => {
                // The trait requires the pk to be in the RFC 9528 compact representation, i.e. just the x coordinate.
                // Here, we reuse the libcrux p256 sec1 compressed decoding and just set the y sign to always
                // be even.
                // This trick is described in https://datatracker.ietf.org/doc/html/rfc9528#name-compact-representation
                // which defines the compact representation.
                if data.len() != 32 {
                    return Err(embedded_cal::ImportError);
                }
                // Sec1 compressed repr first contains an octet designating the sign of y, even = 0x02 or odd = 0x03
                // Then the 32 bytes of the x point, 33 bytes in total.
                const { assert!(SECRET_LEN == 32) };
                let mut sec1_compressed = [0; SECRET_LEN + 1];
                // Set the y sign to even in the sec1 compressed representation
                sec1_compressed[0] = 0x02;
                sec1_compressed[1..].copy_from_slice(data);

                let mut pk = [0; PUBLIC_LEN];
                // compressed_to_raw also checks the validity of (x, y)
                if !compressed_to_raw(&sec1_compressed, &mut pk) {
                    return Err(embedded_cal::ImportError);
                }
                Ok(PublicKey::P256(P256PublicKey(pk)))
            }
            DhAlgorithm::Direct(base_algo) => self
                .0
                .dh()
                .import_publickey_bytes(base_algo, data)
                .map(PublicKey::Direct),
        }
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        match (private, public) {
            (SecretKey::P256(secret), PublicKey::P256(public)) => {
                // FIXME: This feels somewhat like an abuse of the IncompatibleKeys error. P256::derive_ecdh should only
                //  return an error if the keys are invalid, which should be impossible by construction. But the alternative
                // is using an unreachable! here, which would crash the process if that "should be impossible" is wrong.
                let point: [U8; 64] = P256::derive_ecdh(&public.0, &secret.0)
                    .map_err(|_| embedded_cal::IncompatibleKeys)?;
                // P256::derive_ecdh returns the affine point of secret * public in big-endian format concatenated as x||y
                // However, the ECDH shared secret should only be the x coordinate.
                const { assert!(P256_SHARED_SECRET_LEN <= 64) };
                let shared_secret = point
                    .first_chunk()
                    .expect("shared_secret has len 32 <= point len 64");
                Ok(SharedSecret::P256(*shared_secret))
            }
            (SecretKey::Direct(secret), PublicKey::Direct(public)) => self
                .0
                .dh()
                .shared_secret(secret, public)
                .map(SharedSecret::Direct),
            (SecretKey::P256(_), PublicKey::Direct(_))
            | (SecretKey::Direct(_), PublicKey::P256(_)) => Err(embedded_cal::IncompatibleKeys),
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::P256(secret) => PublicKey::P256(P256PublicKey(
                P256::secret_to_public(&secret.0)
                    .expect("Invalid secret key is impossible by construction"),
            )),
            SecretKey::Direct(secret) => PublicKey::Direct(self.0.dh().public_key(secret)),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        match secret {
            SharedSecret::P256(secret) => Either::Own(secret.declassify_ref()),
            SharedSecret::Direct(secret) => Either::Direct(self.0.dh().raw_secret_bytes(secret)),
        }
    }
}

impl<BVSK, BSK> From<VisibleSecretKey<BVSK>> for SecretKey<BSK>
where
    BVSK: Into<BSK>,
{
    fn from(value: VisibleSecretKey<BVSK>) -> Self {
        match value {
            VisibleSecretKey::P256(secret_key) => SecretKey::P256(secret_key),
            VisibleSecretKey::Direct(secret_key) => SecretKey::Direct(secret_key.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use embedded_cal::Cal;

    use crate::{Extender, ExtenderConfig};

    struct TestConfig;

    impl ExtenderConfig for TestConfig {
        type Base = embedded_cal::empty::EmptyCal;
    }

    #[test]
    fn test_dh_ecdh_p256() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);

        embedded_cal::test_dh_algorithm_ecdh_p256::<Extender<TestConfig>>();
        for v in testvectors::dh::RFC5903_P256 {
            v.test_with(cal.dh());
        }
    }
}
