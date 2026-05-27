// FIXME: Something is probably there, just not implemented yet.
//
// (This would be more concise
// <https://github.com/lake-rs/embedded-cal/issues/40> is addressed).

impl embedded_cal::AeadProvider for super::Stm32wba55Cal {
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
