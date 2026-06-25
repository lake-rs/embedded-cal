// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use libcrux_iot_aes::AeadConsts as _;
use libcrux_traits::aead::typed_owned;

use embedded_cal::AeadProvider;

use super::*;

// Used to copy the ciphertext out of the way, and to spool the AAD.
extern crate alloc;
use alloc::{vec, vec::Vec};

pub enum AeadAlgorithm<EC: ExtenderConfig> {
    Direct(AeadAlgorithmOf<EC::Base>),
    AesGcm128,
    AesGcm256,
}

pub enum Key<EC: ExtenderConfig> {
    Direct(AeadKeyOf<EC::Base>),
    AesGcm128(libcrux_iot_aes::AesGcm128Key),
    AesGcm256(libcrux_iot_aes::AesGcm256Key),
}

pub enum Tag<EC: ExtenderConfig> {
    Direct(AeadTagOf<EC::Base>),
    AesGcm128(libcrux_iot_aes::AesGcm128Tag),
    AesGcm256(libcrux_iot_aes::AesGcm256Tag),
}

impl<EC: ExtenderConfig> AeadProvider for Extender<EC> {
    type Algorithm = AeadAlgorithm<EC>;
    type Key = Key<EC>;
    type Tag = Tag<EC>;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::Direct(alg) => Key::Direct(self.0.aead().load_from_keydata(alg, key)),
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
        // Handle the simple case quicly; everything else needs the allocations
        if let Key::Direct(k) = key {
            return Tag::Direct(self.0.aead().encrypt_in_place(k, nonce, message, aad));
        };

        let mut ciphertext = vec![0; message.len()];
        let aad: Vec<_> = aad.items().flatten().copied().collect();

        // I hope this explicitness mess pays off when we run not 2 but many types through
        // the match below.

        fn encrypt<Alg, const T: usize, const N: usize>(
            ciphertext: &mut Vec<u8>,
            key: &typed_owned::Key<Alg>,
            nonce: &[u8],
            aad: &Vec<u8>,
            message: &[u8],
        ) -> typed_owned::Tag<Alg>
        where
            Alg: typed_owned::Aead,
            typed_owned::Tag<Alg>: From<[u8; T]>,
            typed_owned::Nonce<Alg>: From<[u8; N]>,
        {
            let mut tag: typed_owned::Tag<Alg> = [0u8; _].into();
            let nonce: typed_owned::Nonce<Alg> =
                (<[u8; N]>::try_from(nonce).expect("nonce length mismatch")).into();
            Alg::encrypt(
                ciphertext.as_mut_slice(),
                &mut tag,
                key,
                &nonce,
                aad.as_slice(),
                message,
            )
            .expect("slice lenghts match");
            tag
        }

        let tag = match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => Tag::AesGcm128(encrypt::<libcrux_iot_aes::AesGcm128, _, _>(
                &mut ciphertext,
                key,
                nonce,
                &aad,
                message,
            )),
            Key::AesGcm256(key) => Tag::AesGcm256(encrypt::<libcrux_iot_aes::AesGcm256, _, _>(
                &mut ciphertext,
                key,
                nonce,
                &aad,
                message,
            )),
        };
        message.copy_from_slice(&ciphertext);
        tag
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        // Handle the simple case quicly; everything else needs the allocations
        if let Key::Direct(k) = key {
            return self.0.aead().decrypt_in_place(k, nonce, message, tag, aad);
        };

        let mut ciphertext = Vec::from(&*message);
        let aad: Vec<_> = aad.items().flatten().copied().collect();

        // I hope this explicitness mess pays off when we run not 2 but many types through
        // the match below.

        fn decrypt<Alg, const T: usize, const N: usize>(
            ciphertext: &mut Vec<u8>,
            key: &typed_owned::Key<Alg>,
            nonce: &[u8],
            aad: &Vec<u8>,
            message: &mut [u8],
            tag: &[u8],
        ) -> Result<(), embedded_cal::DecryptionFailed>
        where
            Alg: typed_owned::Aead,
            typed_owned::Tag<Alg>: From<[u8; T]>,
            typed_owned::Nonce<Alg>: From<[u8; N]>,
        {
            let tag: typed_owned::Tag<Alg> =
                (<[u8; T]>::try_from(tag).expect("tag length mismatch")).into();
            let nonce: typed_owned::Nonce<Alg> =
                (<[u8; N]>::try_from(nonce).expect("nonce length mismatch")).into();
            Alg::decrypt(
                ciphertext.as_mut_slice(),
                key,
                &nonce,
                aad.as_slice(),
                message,
                &tag,
            )
            .map_err(|_| embedded_cal::DecryptionFailed)
        }

        match key {
            Key::Direct(_) => unreachable!(),
            Key::AesGcm128(key) => decrypt::<libcrux_iot_aes::AesGcm128, _, _>(
                &mut ciphertext,
                key,
                nonce,
                &aad,
                message,
                tag,
            ),
            Key::AesGcm256(key) => decrypt::<libcrux_iot_aes::AesGcm256, _, _>(
                &mut ciphertext,
                key,
                nonce,
                &aad,
                message,
                tag,
            ),
        }
    }
}

impl<EC: ExtenderConfig> embedded_cal::AeadAlgorithm for AeadAlgorithm<EC> {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.key_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::AESGCM128_KEY_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::AESGCM256_KEY_LEN,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.tag_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::AesGcm128::TAG_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::AesGcm256::TAG_LEN,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::Direct(a) => a.nonce_length(),
            AeadAlgorithm::AesGcm128 => libcrux_iot_aes::AesGcm128::NONCE_LEN,
            AeadAlgorithm::AesGcm256 => libcrux_iot_aes::AesGcm256::NONCE_LEN,
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
