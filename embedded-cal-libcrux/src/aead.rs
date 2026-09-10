// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use core::iter::Flatten;

use embedded_cal::{AadGenerator, AeadProvider};

use super::*;

pub enum AeadAlgorithm<EC: ExtenderConfig> {
    Direct(AeadAlgorithmOf<EC::Base>),
    AesGcm128,
    AesGcm256,
    AesCcm128,
    AesCcm128Short,
    AesCcm256,
    AesCcm256Short,
}

pub enum Key<EC: ExtenderConfig> {
    Direct(AeadKeyOf<EC::Base>),
    AesGcm128([u8; libcrux_iot_aes::AES_128_KEY_LEN]),
    AesGcm256([u8; libcrux_iot_aes::AES_256_KEY_LEN]),
    AesCcm128([u8; libcrux_iot_aes::AES_128_KEY_LEN]),
    AesCcm128Short([u8; libcrux_iot_aes::AES_128_KEY_LEN]),
    AesCcm256([u8; libcrux_iot_aes::AES_256_KEY_LEN]),
    AesCcm256Short([u8; libcrux_iot_aes::AES_256_KEY_LEN]),
}

pub enum Tag<EC: ExtenderConfig> {
    Direct(AeadTagOf<EC::Base>),
    AesGcm128([u8; libcrux_iot_aes::TAG_LEN]),
    AesGcm256([u8; libcrux_iot_aes::TAG_LEN]),
    AesCcm128([u8; libcrux_iot_aes::TAG_LEN]),
    AesCcm128Short([u8; libcrux_iot_aes::CCM_SHORT_TAG_LEN]),
    AesCcm256([u8; libcrux_iot_aes::TAG_LEN]),
    AesCcm256Short([u8; libcrux_iot_aes::CCM_SHORT_TAG_LEN]),
}

struct AadAdapter<'a, A: Iterator<Item = &'a [u8]>> {
    inner: Flatten<A>,
    len: usize,
}

impl<'a, A: Iterator<Item = &'a [u8]>> Iterator for AadAdapter<'a, A> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().copied()
    }
}

impl<'a, A: Iterator<Item = &'a [u8]>> ExactSizeIterator for AadAdapter<'a, A> {
    fn len(&self) -> usize {
        self.len
    }
}

fn flatten<T: AadGenerator>(generator: &T) -> AadAdapter<'_, impl Iterator<Item = &[u8]>> {
    let mut len = 0;

    // get the length once
    for chunk in generator.items() {
        len += chunk.len();
    }

    let non_empty_chunks = generator.items().filter(|c| !c.is_empty()).flatten();

    AadAdapter {
        inner: non_empty_chunks,
        len,
    }
}

impl<EC: ExtenderConfig> AeadProvider for Extender<EC> {
    type Algorithm = AeadAlgorithm<EC>;
    type Key = Key<EC>;
    type Tag = Tag<EC>;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        fn convert<const N: usize>(key: &[u8]) -> [u8; N] {
            <[u8; N]>::try_from(key).expect("key length mismatch")
        }

        match alg {
            AeadAlgorithm::Direct(alg) => Key::Direct(self.0.aead().load_from_keydata(alg, key)),
            AeadAlgorithm::AesGcm128 => Key::AesGcm128(convert(key)),
            AeadAlgorithm::AesGcm256 => Key::AesGcm256(convert(key)),
            AeadAlgorithm::AesCcm128 => Key::AesCcm128(convert(key)),
            AeadAlgorithm::AesCcm128Short => Key::AesCcm128Short(convert(key)),
            AeadAlgorithm::AesCcm256 => Key::AesCcm256(convert(key)),
            AeadAlgorithm::AesCcm256Short => Key::AesCcm256Short(convert(key)),
        }
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        if let Key::Direct(k) = key {
            return Tag::Direct(self.0.aead().encrypt_in_place(k, nonce, message, aad));
        };

        macro_rules! encrypt {
            ($module:ident, $tag_len:expr, $key:expr) => {{
                let mut tag = [0u8; $tag_len];
                libcrux_iot_aes::portable::$module::encrypt(
                    $key,
                    nonce,
                    flatten(&aad),
                    message,
                    &mut tag,
                )
                .unwrap();
                tag
            }};
        }

        match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => {
                let tag = encrypt!(aes_gcm_128, libcrux_iot_aes::TAG_LEN, key);
                Tag::AesGcm128(tag)
            }
            Key::AesGcm256(key) => {
                let tag = encrypt!(aes_gcm_256, libcrux_iot_aes::TAG_LEN, key);
                Tag::AesGcm256(tag)
            }
            Key::AesCcm128(key) => {
                let tag = encrypt!(aes_ccm_128, libcrux_iot_aes::TAG_LEN, key);
                Tag::AesCcm128(tag)
            }
            Key::AesCcm128Short(key) => {
                let tag = encrypt!(aes_ccm_128_8, libcrux_iot_aes::CCM_SHORT_TAG_LEN, key);
                Tag::AesCcm128Short(tag)
            }
            Key::AesCcm256(key) => {
                let tag = encrypt!(aes_ccm_256, libcrux_iot_aes::TAG_LEN, key);
                Tag::AesCcm256(tag)
            }
            Key::AesCcm256Short(key) => {
                let tag = encrypt!(aes_ccm_256_8, libcrux_iot_aes::CCM_SHORT_TAG_LEN, key);
                Tag::AesCcm256Short(tag)
            }
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
        if let Key::Direct(k) = key {
            return self.0.aead().decrypt_in_place(k, nonce, message, tag, aad);
        };

        macro_rules! decrypt {
            ($module:ident, $key:expr) => {
                libcrux_iot_aes::portable::$module::decrypt(
                    $key,
                    nonce,
                    flatten(&aad),
                    message,
                    tag,
                )
                .map_err(|_| embedded_cal::DecryptionFailed)?
            };
        }

        match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => decrypt!(aes_gcm_128, key),
            Key::AesGcm256(key) => decrypt!(aes_gcm_256, key),
            Key::AesCcm128(key) => decrypt!(aes_ccm_128, key),
            Key::AesCcm128Short(key) => decrypt!(aes_ccm_128_8, key),
            Key::AesCcm256(key) => decrypt!(aes_ccm_256, key),
            Key::AesCcm256Short(key) => decrypt!(aes_ccm_256_8, key),
        }

        Ok(())
    }
}

impl<EC: ExtenderConfig> embedded_cal::AeadAlgorithm for AeadAlgorithm<EC> {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.key_length(),
            AeadAlgorithm::AesGcm128 | AeadAlgorithm::AesCcm128 | AeadAlgorithm::AesCcm128Short => {
                libcrux_iot_aes::AES_128_KEY_LEN
            }
            AeadAlgorithm::AesCcm256 | AeadAlgorithm::AesCcm256Short | AeadAlgorithm::AesGcm256 => {
                libcrux_iot_aes::AES_256_KEY_LEN
            }
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.tag_length(),
            AeadAlgorithm::AesGcm128
            | AeadAlgorithm::AesGcm256
            | AeadAlgorithm::AesCcm128
            | AeadAlgorithm::AesCcm256 => libcrux_iot_aes::TAG_LEN,
            AeadAlgorithm::AesCcm128Short | AeadAlgorithm::AesCcm256Short => {
                libcrux_iot_aes::CCM_SHORT_TAG_LEN
            }
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.nonce_length(),
            AeadAlgorithm::AesCcm128
            | AeadAlgorithm::AesCcm128Short
            | AeadAlgorithm::AesCcm256
            | AeadAlgorithm::AesCcm256Short
            | AeadAlgorithm::AesGcm128
            | AeadAlgorithm::AesGcm256 => libcrux_iot_aes::NONCE_LEN,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number = number.into();
        match number {
            1 => Some(AeadAlgorithm::AesGcm128),
            3 => Some(AeadAlgorithm::AesGcm256),
            _ => AeadAlgorithmOf::<EC::Base>::from_cose_number(number).map(AeadAlgorithm::Direct),
        }
    }
}

impl<EC: ExtenderConfig> Clone for AeadAlgorithm<EC> {
    // This is the default implementation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::Direct(arg0) => Self::Direct(arg0.clone()),
            Self::AesGcm128 => Self::AesGcm128,
            Self::AesGcm256 => Self::AesGcm256,
            Self::AesCcm128 => Self::AesCcm128,
            Self::AesCcm128Short => Self::AesCcm128Short,
            Self::AesCcm256 => Self::AesCcm256,
            Self::AesCcm256Short => Self::AesCcm256Short,
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
            Self::AesCcm128 => f.write_str("AesCcm128"),
            Self::AesCcm128Short => f.write_str("AesCcm128Short"),
            Self::AesCcm256 => f.write_str("AesCcm256"),
            Self::AesCcm256Short => f.write_str("AesCcm256Short"),
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
            Tag::AesCcm128(tag) => tag.as_ref(),
            Tag::AesCcm128Short(tag) => tag.as_ref(),
            Tag::AesCcm256(tag) => tag.as_ref(),
            Tag::AesCcm256Short(tag) => tag.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Extender, ExtenderConfig};

    struct TestConfig;

    impl ExtenderConfig for TestConfig {
        type Base = embedded_cal::empty::EmptyCal;
    }

    #[test]
    fn test_aes_gcm_128_encrypt_decrypt() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::test_aead_aesgcm_128(&mut cal);
    }

    #[test]
    fn test_aes_gcm_256_encrypt_decrypt() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::test_aead_aesgcm_256(&mut cal);
    }
}
