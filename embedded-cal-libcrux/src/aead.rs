// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use core::iter::Flatten;

use embedded_cal::{AadGenerator, AeadProvider};

use super::*;

pub enum AeadAlgorithm<EC: ExtenderConfig> {
    Direct(AeadAlgorithmOf<EC::Base>),
    AesGcm128,
    AesGcm256,
}

pub enum Key<EC: ExtenderConfig> {
    Direct(AeadKeyOf<EC::Base>),
    AesGcm128([u8; libcrux_iot_aes::AES_128_KEY_LEN]),
    AesGcm256([u8; libcrux_iot_aes::AES_256_KEY_LEN]),
}

pub enum Tag<EC: ExtenderConfig> {
    Direct(AeadTagOf<EC::Base>),
    AesGcm128([u8; libcrux_iot_aes::TAG_LEN]),
    AesGcm256([u8; libcrux_iot_aes::TAG_LEN]),
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
        match alg {
            AeadAlgorithm::Direct(alg) => Key::Direct(self.0.aead().load_from_keydata(alg, key)),
            AeadAlgorithm::AesGcm128 => {
                Key::AesGcm128(<[u8; _]>::try_from(key).expect("key length mismatch"))
            }
            AeadAlgorithm::AesGcm256 => {
                Key::AesGcm256(<[u8; _]>::try_from(key).expect("key length mismatch"))
            }
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

        match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => {
                let mut tag = [0u8; libcrux_iot_aes::TAG_LEN];
                libcrux_iot_aes::portable::aes_gcm_128::encrypt(
                    key,
                    nonce,
                    flatten(&aad),
                    message,
                    &mut tag,
                )
                .unwrap();
                Tag::AesGcm128(tag)
            }
            Key::AesGcm256(key) => {
                let mut tag = [0u8; libcrux_iot_aes::TAG_LEN];
                libcrux_iot_aes::portable::aes_gcm_256::encrypt(
                    key,
                    nonce,
                    flatten(&aad),
                    message,
                    &mut tag,
                )
                .unwrap();
                Tag::AesGcm256(tag)
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

        match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => libcrux_iot_aes::portable::aes_gcm_128::decrypt(
                key,
                nonce,
                flatten(&aad),
                message,
                tag,
            )
            .map_err(|_| embedded_cal::DecryptionFailed)?,
            Key::AesGcm256(key) => libcrux_iot_aes::portable::aes_gcm_256::decrypt(
                key,
                nonce,
                flatten(&aad),
                message,
                tag,
            )
            .map_err(|_| embedded_cal::DecryptionFailed)?,
        }

        Ok(())
    }
}

impl<EC: ExtenderConfig> embedded_cal::AeadAlgorithm for AeadAlgorithm<EC> {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.key_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::AES_128_KEY_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::AES_256_KEY_LEN,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.tag_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::TAG_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::TAG_LEN,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.nonce_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::NONCE_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::NONCE_LEN,
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
