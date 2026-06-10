//! All the impls of Cal that the libcrux extender does *not* really provide.
//!
//! (This should be small enough to inline back into the top module when
//! <https://github.com/lake-rs/embedded-cal/issues/40> is addressed).

use super::*;

impl<EC: ExtenderConfig> embedded_cal::HmacProvider for Extender<EC> {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type Key = embedded_cal::empty::NoAlgorithms;
    type HmacState = embedded_cal::empty::NoAlgorithms;
    type HmacResult = embedded_cal::empty::NoAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::HmacState {
        match key {}
    }

    fn update(&mut self, state: &mut Self::HmacState, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        match state {}
    }
}

impl<EC: ExtenderConfig> embedded_cal::AeadProvider for Extender<EC> {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type Key = embedded_cal::empty::NoAlgorithms;
    type Tag = embedded_cal::empty::NoAlgorithms;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match alg {}
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        match *key {}
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        match *key {}
    }
}

impl<EC: ExtenderConfig> embedded_cal::DhProvider for Extender<EC> {
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
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        match *secret {};
        &[]
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
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
    ) -> impl AsRef<[u8]> + use<'p, EC> {
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
