use libcrux_aesgcm::AeadConsts;

use embedded_cal::AeadProvider;

use super::*;

pub enum AeadAlgorithm<EC: ExtenderConfig> {
    Direct(<EC::Base as AeadProvider>::Algorithm),
    AesGcm128,
    AesGcm256,
}

pub enum Key<EC: ExtenderConfig> {
    Direct(<EC::Base as AeadProvider>::Key),
    AesGcm128(libcrux_aesgcm::AesGcm128Key),
    AesGcm256(libcrux_aesgcm::AesGcm256Key),
}

pub enum Tag<EC: ExtenderConfig> {
    Direct(<EC::Base as AeadProvider>::Tag),
    AesGcm128(libcrux_aesgcm::AesGcm128Tag),
    AesGcm256(libcrux_aesgcm::AesGcm256Tag),
}

impl<EC: ExtenderConfig> embedded_cal::AeadProvider for Extender<EC> {
    type Algorithm = AeadAlgorithm<EC>;
    type Key = Key<EC>;
    type Tag = Tag<EC>;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::Direct(alg) => Key::Direct(self.0.load_from_keydata(alg, key)),
            AeadAlgorithm::AesGcm128 => Key::AesGcm128(
                <[u8; _]>::try_from(key)
                    .expect("key length mismatch")
                    .into(),
            ),
            AeadAlgorithm::AesGcm256 => Key::AesGcm256(
                <[u8; _]>::try_from(key)
                    .expect("key length mismatch")
                    .into(),
            ),
        }
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        match key {
            Key::Direct(k) => Tag::Direct(self.0.encrypt_in_place(k, nonce, message, aad)),
            Key::AesGcm128(key) => todo!(),
            Key::AesGcm256(key) => todo!(),
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        match key {
            Key::Direct(k) => self.0.decrypt_in_place(k, nonce, message, tag, aad),
            Key::AesGcm128(key) => todo!(),
            Key::AesGcm256(key) => todo!(),
        }
    }
}

impl<EC: ExtenderConfig> embedded_cal::AeadAlgorithm for AeadAlgorithm<EC> {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.key_length(),
            AeadAlgorithm::AesGcm128 => libcrux_aesgcm::AESGCM128_KEY_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_aesgcm::AESGCM256_KEY_LEN,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.tag_length(),
            AeadAlgorithm::AesGcm128 => libcrux_aesgcm::AesGcm128::TAG_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_aesgcm::AesGcm256::TAG_LEN,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.nonce_length(),
            AeadAlgorithm::AesGcm128 => libcrux_aesgcm::AesGcm128::NONCE_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_aesgcm::AesGcm256::NONCE_LEN,
        }
    }
}

impl<EC: ExtenderConfig> Clone for AeadAlgorithm<EC> {
    // This is the default implemnentation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::Direct(arg0) => Self::Direct(arg0.clone()),
            Self::AesGcm128 => Self::AesGcm128,
            Self::AesGcm256 => Self::AesGcm256,
        }
    }
}

impl<EC: ExtenderConfig> core::fmt::Debug for AeadAlgorithm<EC> {
    // As for Clone
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct(arg0) => arg0.fmt(f),
            Self::AesGcm128 => f.write_str("AesGcm128"),
            Self::AesGcm256 => f.write_str("AesGcm256"),
        }
    }
}

impl<EC: ExtenderConfig> PartialEq for AeadAlgorithm<EC> {
    // As for Clone
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct(l0), Self::Direct(r0)) => l0 == r0,
            (Self::AesGcm128, Self::AesGcm128) => true,
            (Self::AesGcm256, Self::AesGcm256) => true,
            _ => false,
        }
    }
}

impl<EC: ExtenderConfig> Eq for AeadAlgorithm<EC> {}

impl<EC: ExtenderConfig> AsRef<[u8]> for Tag<EC> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Tag::Direct(tag) => tag.as_ref(),
            Tag::AesGcm128(tag) => tag.as_ref(),
            Tag::AesGcm256(tag) => tag.as_ref(),
        }
    }
}
