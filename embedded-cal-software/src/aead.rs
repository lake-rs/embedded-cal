use embedded_cal::AeadProvider;

use super::{Extender, ExtenderConfig};

/// Right now, this is just forwarding, as there is no plumbing yet to build on.
impl<EC: ExtenderConfig> AeadProvider for Extender<EC> {
    type Algorithm = <EC::Base as AeadProvider>::Algorithm;
    type Key = <EC::Base as AeadProvider>::Key;
    type Tag = <EC::Base as AeadProvider>::Tag;

    fn load_from_keydata(&mut self, _alg: Self::Algorithm, _key: &[u8]) -> Self::Key {
        todo!()
    }

    fn encrypt_in_place(
        &mut self,
        _key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        todo!()
    }

    fn decrypt_in_place(
        &mut self,
        _key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        todo!()
    }
}
