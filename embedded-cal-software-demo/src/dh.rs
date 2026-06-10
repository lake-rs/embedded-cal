use embedded_cal::DhProvider;

use super::{Extender, ExtenderConfig};

/// Right now, this is just forwarding, as there is no plumbing yet to build on.
impl<EC: ExtenderConfig> DhProvider for Extender<EC> {
    type DhAlgorithm = <EC::Base as DhProvider>::DhAlgorithm;
    type VisibleSecretKey = <EC::Base as DhProvider>::VisibleSecretKey;
    type SecretKey = <EC::Base as DhProvider>::SecretKey;
    type PublicKey = <EC::Base as DhProvider>::PublicKey;
    type SharedSecret = <EC::Base as DhProvider>::SharedSecret;

    fn generate_visible(&mut self, alg: Self::DhAlgorithm) -> Self::VisibleSecretKey {
        self.0.generate_visible(alg)
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        self.0.shared_secret(private, public)
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        self.0.public_key(private)
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        self.0.raw_secret_bytes(secret)
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        self.0.export_secretkey_bytes(secretkey)
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::DhAlgorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        self.0.import_secretkey_bytes(alg, secret)
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        self.0.export_publickey_bytes(public)
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::DhAlgorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        self.0.import_publickey_bytes(alg, data)
    }
}
