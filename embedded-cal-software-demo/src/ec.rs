// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

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
}

pub enum SecretKey<BSK> {
    SoftwareP256([u8; 32]),
    SoftwareX25519([u8; 32]),
    SoftwareX448([u8; 56]),
    Direct(BSK),
}

pub enum VisibleSecretKey<BSK> {
    SoftwareP256([u8; 32]),
    SoftwareX25519([u8; 32]),
    SoftwareX448([u8; 56]),
    Direct(BSK),
}

impl<BSK1: Into<BSK2>, BSK2> From<VisibleSecretKey<BSK1>> for SecretKey<BSK2> {
    fn from(value: VisibleSecretKey<BSK1>) -> Self {
        match value {
            VisibleSecretKey::SoftwareP256(v) => SecretKey::SoftwareP256(v),
            VisibleSecretKey::SoftwareX25519(v) => SecretKey::SoftwareX25519(v),
            VisibleSecretKey::SoftwareX448(v) => SecretKey::SoftwareX448(v),
            VisibleSecretKey::Direct(v) => SecretKey::Direct(v.into()),
        }
    }
}

pub enum PublicKey<BPK> {
    SoftwareP256([u8; 32]),
    SoftwareX25519([u8; 32]),
    SoftwareX448([u8; 56]),
    Direct(BPK),
}

pub enum SharedSecret<BSS> {
    SoftwareP256([u8; 32]),
    SoftwareX25519([u8; 32]),
    SoftwareX448([u8; 56]),
    Direct(BSS),
}

impl<EC: ExtenderConfig> DhProvider for Extender<EC> {
    type Algorithm = Algorithm<EC>;
    type VisibleSecretKey = VisibleSecretKey<DhVisibleSecretKeyOf<EC::Base>>;
    type SecretKey = SecretKey<DhSecretKeyOf<EC::Base>>;
    type PublicKey = PublicKey<DhPublicKeyOf<EC::Base>>;
    type SharedSecret = SharedSecret<DhPublicKeyOf<EC::Base>>;

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
        #[allow(unreachable_code)]
        &[]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let _ = (alg, secret);
        todo!("not covered by test vectors")
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        let _ = public;
        todo!("not covered by test vectors");
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
        let _ = secret;
        todo!("not covered by test vectors");
        #[allow(unreachable_code)]
        &[]
    }
}
