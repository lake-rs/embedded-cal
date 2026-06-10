use super::*;

impl embedded_cal::DhProvider for Stm32wba55Cal {
    type DhAlgorithm = embedded_cal::empty::NoAlgorithms;
    type VisibleSecretKey = embedded_cal::empty::NoAlgorithms;
    type SecretKey = embedded_cal::empty::NoAlgorithms;
    type PublicKey = embedded_cal::empty::NoAlgorithms;
    type SharedSecret = embedded_cal::empty::NoAlgorithms;

    fn generate_visible(&mut self, alg: Self::DhAlgorithm) -> Self::VisibleSecretKey {
        match alg {}
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        _public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        match *private {}
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match *private {}
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        match *secret {};
        &[]
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        match *secretkey {};
        &[]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::DhAlgorithm,
        _secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        match alg {}
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        match *public {};
        &[]
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::DhAlgorithm,
        _data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        match alg {}
    }
}
