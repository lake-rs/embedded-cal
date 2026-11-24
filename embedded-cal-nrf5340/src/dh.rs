// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Key establishment on top of the EC plumbing in [`crate::dh_plumbing`], whose scalar
//! multiplications run on the PKA (see [`crate::ec`]).

use embedded_cal::plumbing::ec::{Ec, EcPrimitives};
use embedded_cal::util::montgomery::{clamp_x448, clamp_x25519, mask_u_x25519};
use embedded_cal::util::p256::{P256_GX_BYTES, P256_GY_BYTES, p256_recover_y};
use rand_core::Rng as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Debug, Clone, Zeroize)]
pub enum DhAlgorithm {
    EcdhP256,
    X25519,
    X448,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::EcdhP256 | DhAlgorithm::X25519 => 32,
            DhAlgorithm::X448 => 56,
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        match curve.into() {
            1 => Some(DhAlgorithm::EcdhP256),
            4 => Some(DhAlgorithm::X25519),
            5 => Some(DhAlgorithm::X448),
            _ => None,
        }
    }
}

/// It is an invariant of this type that algorithm specific preconditions are upheld, concretely:
///
/// * RFC7748 curve keys (x25519, x448) are pre-clamped as in that document's decodeScalar
///   functions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SecretKey {
    EcdhP256(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::P256>),
    X25519(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::X25519>),
    X448(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::X448>),
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

/// It is an invariant of this type that algorithm specific preconditions are upheld, concretely:
///
/// * RFC7748 curve keys have their unused bits cleared where applicable  (x25519; doesn't apply to
///   x448 because its length is divisible by 8).
// This is a *bit* wasteful because y is large enough even to hold a y coordinate of an OKP key;
// right now my gut feeling is that the simplifications from keeping this type simple outweigh
// that -- but maybe not, and we should switch to having an NrfScalar in there. (Shouldn't matter
// too much for the layout, and accessing x will still be the same).
//
// (We could deviate from the pattern here, as what matters is usually accessing .x, but then we'd
// also have to change the point type because the multiply_scalar_point API expects a point)
pub enum PublicKey {
    EcdhP256(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::P256>),
    X25519(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::X25519>),
    X448(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::X448>),
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; <super::Nrf5340Cal as Ec>::MAX_SCALAR_LENGTH],
    len: usize,
}

impl SharedSecret {
    fn from_x_coordinate<CAL: EcPrimitives<C>, C: crate::dh_plumbing::NrfCurve>(
        plumbing: &mut CAL,
        point: &CAL::Point,
    ) -> Self {
        // In this module we could, as an optimization, reach right for point.x.data, but moving towards a
        // more reusable higher-layer, we accept the copying/zeroing.
        //
        // FIXME: How can we retain such optimizations going to a generic software layer?
        let x = plumbing.x_coord(point);
        let x = plumbing.export_scalar_bytes(&x);
        let mut bytes = [0; _];
        bytes[..C::SCALAR_SIZE].copy_from_slice(x.as_ref());
        SharedSecret {
            bytes,
            len: C::SCALAR_SIZE,
        }
    }
}

// Not needed per se, but useful because we can thus internally reuse it as the return type of
// export_publickey_bytes.
impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl embedded_cal::DhProvider for super::Nrf5340Cal {
    type Algorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            // No rejection loop on the secret candidate; see `p256_random_scalar`.
            DhAlgorithm::EcdhP256 => {
                VisibleSecretKey(SecretKey::EcdhP256(self.p256_random_scalar().into()))
            }
            DhAlgorithm::X25519 => {
                let mut scalar = [0u8; 32];
                self.fill_bytes(&mut scalar);
                clamp_x25519(&mut scalar);
                VisibleSecretKey(SecretKey::X25519(scalar.into()))
            }
            DhAlgorithm::X448 => {
                let mut scalar = [0u8; 56];
                self.fill_bytes(&mut scalar);
                clamp_x448(&mut scalar);
                VisibleSecretKey(SecretKey::X448(scalar.into()))
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        match &secretkey.0 {
            SecretKey::EcdhP256(scalar) => scalar.as_ref().as_slice(),
            SecretKey::X25519(scalar) => scalar.as_ref().as_slice(),
            SecretKey::X448(scalar) => scalar.as_ref().as_slice(),
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let secret = match alg {
            DhAlgorithm::EcdhP256 => SecretKey::EcdhP256(
                <[u8; _]>::try_from(secret)
                    .map_err(|_| embedded_cal::ImportError)?
                    .into(),
            ),
            DhAlgorithm::X25519 => {
                let mut scalar =
                    <[u8; _]>::try_from(secret).map_err(|_| embedded_cal::ImportError)?;
                // RFC7748 says "Implementations MUST accept non-canonical values" about public
                // keys, and has no concrete words around loading secret keys (which is not really
                // a necessary operation anyway); following the same notational logic (data is
                // clipped silently), we also do not err here.
                clamp_x25519(&mut scalar);
                SecretKey::X25519(scalar.into())
            }
            DhAlgorithm::X448 => {
                let mut scalar =
                    <[u8; _]>::try_from(secret).map_err(|_| embedded_cal::ImportError)?;
                clamp_x448(&mut scalar);
                SecretKey::X448(scalar.into())
            }
        };
        Ok(VisibleSecretKey(secret))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        // In this module, we could also unconditionall return `point.x.as_ref().as_slice()` for
        // all 3 branches of a `match public`, and that'd be effectively a no-op.
        //
        // FIXME: How can we retain such optimizations going to a generic software layer? Can (or
        // should) the software layer demand that the AsRef type is the same across all C? (Then it
        // could be `self.p256().export_scalar_bytes(&self.p256().x_coord(point))`)

        // As a code-reusing solution to at least not work around that limitation twice, we're
        // reusing SharedSecret internally.

        match public {
            PublicKey::EcdhP256(point) => SharedSecret::from_x_coordinate(self.p256(), point),
            PublicKey::X25519(point) => SharedSecret::from_x_coordinate(self.x25519(), point),
            PublicKey::X448(point) => SharedSecret::from_x_coordinate(self.x448(), point),
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        match alg {
            DhAlgorithm::EcdhP256 => {
                let x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                let y = p256_recover_y(&x)?;
                Ok(PublicKey::EcdhP256(self.p256().point(x.into(), y.into())))
            }
            DhAlgorithm::X25519 => {
                let mut x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                mask_u_x25519(&mut x);
                Ok(PublicKey::X25519(
                    self.x25519().point(x.into(), [0; _].into()),
                ))
            }
            DhAlgorithm::X448 => {
                let x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                Ok(PublicKey::X448(self.x448().point(x.into(), [0; _].into())))
            }
        }
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        match (private, public) {
            (SecretKey::EcdhP256(private), PublicKey::EcdhP256(public)) => {
                let result = self.p256().multiply_scalar_point(private, public);
                Ok(SharedSecret::from_x_coordinate(self.p256(), &result))
            }
            (SecretKey::X25519(k), PublicKey::X25519(public)) => {
                // Not clamping of k: Was done at generation / loading time.
                // No clearing of the 256 bit of the public key: Was done at loading time.
                let result = self.x25519().multiply_scalar_point(k, public);
                Ok(SharedSecret::from_x_coordinate(self.x25519(), &result))
            }
            (SecretKey::X448(k), PublicKey::X448(public)) => {
                // Not clamping of k: Was done at generation / loading time.
                let result = self.x448().multiply_scalar_point(k, public);
                Ok(SharedSecret::from_x_coordinate(self.x448(), &result))
            }
            _ => Err(embedded_cal::IncompatibleKeys),
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        use crate::dh_plumbing::NrfScalar;
        use embedded_cal::plumbing::ec::*;

        match private {
            SecretKey::EcdhP256(scalar) => {
                let base = self.p256().point(
                    NrfScalar::<P256>::from(P256_GX_BYTES),
                    NrfScalar::<P256>::from(P256_GY_BYTES),
                );
                PublicKey::EcdhP256(self.p256().multiply_scalar_point(scalar, &base))
            }
            SecretKey::X25519(k) => {
                let mut base_u = [0u8; 32];
                base_u[0] = 9; // X25519 base point u-coordinate = 9 (little-endian)
                let base = self.x25519().point(base_u.into(), [0; _].into());
                let public = self.x25519().multiply_scalar_point(k, &base);
                // FIXME: Verify that the output key needs no bit-clearing (because it is on the
                // curve by construction)
                PublicKey::X25519(public)
            }
            SecretKey::X448(k) => {
                let mut base_u = [0u8; 56];
                base_u[0] = 5; // X448 base point u-coordinate = 5 (little-endian)
                let base = self.x448().point(base_u.into(), [0; _].into());
                PublicKey::X448(self.x448().multiply_scalar_point(k, &base))
            }
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        secret.as_ref()
    }
}
