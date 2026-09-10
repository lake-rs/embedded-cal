// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::plumbing::ec::{Ec, EcPrimitives, P256, X448, X25519};
use embedded_cal::{Cal, DhAlgorithm, DhProvider, accessor::*};

use super::{Extender, ExtenderConfig};

pub enum Algorithm<EC: ExtenderConfig> {
    // FIXME: As with all these structs, this better respect IMPLEMENT_DH
    SoftwareP256,
    SoftwareX25519,
    SoftwareX448,
    Direct(DhAlgorithmOf<EC::Base>),
}

impl<EC: ExtenderConfig> Clone for Algorithm<EC> {
    // This is the default implemnentation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::SoftwareP256 => Self::SoftwareP256,
            Self::SoftwareX25519 => Self::SoftwareX25519,
            Self::SoftwareX448 => Self::SoftwareX448,
            Self::Direct(a) => Self::Direct(a.clone()),
        }
    }
}

impl<EC: ExtenderConfig> core::fmt::Debug for Algorithm<EC> {
    // As for Clone
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SoftwareP256 => write!(f, "SoftwareP256"),
            Self::SoftwareX25519 => write!(f, "SoftwareX25519"),
            Self::SoftwareX448 => write!(f, "SoftwareX448"),
            Self::Direct(arg0) => f.debug_tuple("Direct").field(arg0).finish(),
        }
    }
}

impl<EC: ExtenderConfig> PartialEq for Algorithm<EC> {
    // As for Clone
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct(l0), Self::Direct(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl<EC: ExtenderConfig> Eq for Algorithm<EC> {}

impl<EC: ExtenderConfig> DhAlgorithm for Algorithm<EC> {
    fn output_length(&self) -> usize {
        match self {
            Algorithm::SoftwareP256 => 32,
            Algorithm::SoftwareX25519 => 32,
            Algorithm::SoftwareX448 => 56,
            Algorithm::Direct(d) => d.output_length(),
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        let curve: i128 = curve.into();

        match curve.into() {
            1 if EC::IMPLEMENT_DH => Some(Algorithm::SoftwareP256),
            4 if EC::IMPLEMENT_DH => Some(Algorithm::SoftwareX25519),
            5 if EC::IMPLEMENT_DH => Some(Algorithm::SoftwareX448),
            _ => DhAlgorithmOf::<EC::Base>::from_cose_ecdh(curve).map(Algorithm::Direct),
        }
    }
}

pub enum SecretKey<EC: ExtenderConfig> {
    SoftwareP256(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Scalar,
    ),
    SoftwareX25519(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX25519 as EcPrimitives<X25519>>::Scalar,
    ),
    SoftwareX448(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX448 as EcPrimitives<X448>>::Scalar,
    ),
    Direct(<DhProviderOf<EC::Base> as DhProvider>::SecretKey),
}

pub enum VisibleSecretKey<EC: ExtenderConfig> {
    SoftwareP256(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Scalar,
    ),
    SoftwareX25519(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX25519 as EcPrimitives<X25519>>::Scalar,
    ),
    SoftwareX448(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX448 as EcPrimitives<X448>>::Scalar,
    ),
    Direct(<DhProviderOf<EC::Base> as DhProvider>::VisibleSecretKey),
}

impl<EC: ExtenderConfig> From<VisibleSecretKey<EC>> for SecretKey<EC> {
    fn from(value: VisibleSecretKey<EC>) -> Self {
        match value {
            VisibleSecretKey::SoftwareP256(v) => SecretKey::SoftwareP256(v),
            VisibleSecretKey::SoftwareX25519(v) => SecretKey::SoftwareX25519(v),
            VisibleSecretKey::SoftwareX448(v) => SecretKey::SoftwareX448(v),
            VisibleSecretKey::Direct(v) => SecretKey::Direct(v.into()),
        }
    }
}

pub enum PublicKey<EC: ExtenderConfig> {
    SoftwareP256(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Scalar,
    ),
    SoftwareX25519(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX25519 as EcPrimitives<X25519>>::Scalar,
    ),
    SoftwareX448(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX448 as EcPrimitives<X448>>::Scalar,
    ),
    Direct(<DhProviderOf<EC::Base> as DhProvider>::PublicKey),
}

pub enum SharedSecret<EC: ExtenderConfig> {
    SoftwareP256(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Scalar,
    ),
    SoftwareX25519(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX25519 as EcPrimitives<X25519>>::Scalar,
    ),
    SoftwareX448(
        <<<EC as ExtenderConfig>::Base as Ec>::PrimitivesX448 as EcPrimitives<X448>>::Scalar,
    ),
    Direct(<DhProviderOf<EC::Base> as DhProvider>::SharedSecret),
}

impl<EC: ExtenderConfig> DhProvider for Extender<EC> {
    type Algorithm = Algorithm<EC>;
    type VisibleSecretKey = VisibleSecretKey<EC>;
    type SecretKey = SecretKey<EC>;
    type PublicKey = PublicKey<EC>;
    type SharedSecret = SharedSecret<EC>;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            Algorithm::SoftwareP256 => todo!("not covered by test vectors"),
            Algorithm::SoftwareX25519 => todo!("not covered by test vectors"),
            Algorithm::SoftwareX448 => todo!("not covered by test vectors"),
            Algorithm::Direct(a) => VisibleSecretKey::Direct(self.0.dh().generate_visible(a)),
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        let _ = secretkey;
        todo!("not covered by test vectors");
        // A real implementation would look very similar to raw_secret_bytes
        #[allow(unreachable_code)]
        &[]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        match alg {
            Algorithm::SoftwareP256 => {
                let p256 = self.0.p256();
                Ok(VisibleSecretKey::SoftwareP256(
                    p256.import_scalar_bytes(secret)?,
                ))
            }
            Algorithm::SoftwareX25519 => todo!(),
            Algorithm::SoftwareX448 => todo!(),
            Algorithm::Direct(a) => self
                .0
                .dh()
                .import_secretkey_bytes(a, secret)
                .map(VisibleSecretKey::Direct),
        }
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        let _ = public;
        todo!("not covered by test vectors");
        // A real implementation would look very similar to raw_secret_bytes
        #[allow(unreachable_code)]
        &[]
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        let _ = (alg, data);
        todo!("not covered by test vectors")
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        let _ = (private, public);
        todo!("not covered by test vectors")
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let _ = private;
        todo!("not covered by test vectors")
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        enum Local<S1: AsRef<[u8]>, S2: AsRef<[u8]>, S3: AsRef<[u8]>, D: AsRef<[u8]>> {
            SoftwareP256(S1),
            SoftwareX25519(S2),
            SoftwareX448(S3),
            Direct(D),
        }
        impl<S1: AsRef<[u8]>, S2: AsRef<[u8]>, S3: AsRef<[u8]>, D: AsRef<[u8]>> AsRef<[u8]>
            for Local<S1, S2, S3, D>
        {
            fn as_ref(&self) -> &[u8] {
                match self {
                    Local::SoftwareP256(v) => v.as_ref(),
                    Local::SoftwareX25519(v) => v.as_ref(),
                    Local::SoftwareX448(v) => v.as_ref(),
                    Local::Direct(v) => v.as_ref(),
                }
            }
        }
        match secret {
            SharedSecret::SoftwareP256(s) => {
                Local::SoftwareP256(self.p256().export_scalar_bytes(s))
            }
            SharedSecret::SoftwareX25519(s) => {
                Local::SoftwareX25519(self.x25519().export_scalar_bytes(s))
            }
            SharedSecret::SoftwareX448(s) => {
                Local::SoftwareX448(self.x448().export_scalar_bytes(s))
            }
            SharedSecret::Direct(s) => Local::Direct(self.0.dh().raw_secret_bytes(s)),
        }
    }
}
