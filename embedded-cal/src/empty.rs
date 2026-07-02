// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Implementations of the various traits of embedded-cal that implemnt the empty set of
//! algorithms.
//!
//! The types are ZST or uninhabited as suitable for the type.

use super::*;

/// An implementation of [`Cal`] that provides no single algorithm.
///
/// It implements all the individual traits, as well as the full `Cal` trait. The former is useful
/// for hardware implementations that don't touch an area at all; the latter is useful in testing
/// or when an extender is used standalone.
pub struct EmptyCal<const PLUMBING: bool>;

impl<const PLUMBING: bool> Cal for EmptyCal<PLUMBING> {
    type DhProvider = Self;
    type AeadProvider = Self;
    type HashProvider = Self;
    type HmacProvider = Self;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self
    }
}

// Those should all be shorter when <https://github.com/lake-rs/embedded-cal/issues/40> is
// resolved; then again, the implementations that do make it short will live here. Until then, feel
// free to copy those out into your Cal implementations.

impl<const PLUMBING: bool> HashProvider for EmptyCal<PLUMBING> {
    type Algorithm = NoAlgorithms;
    type State = NoAlgorithms;
    type Output = NoAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::State, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::State) -> Self::Output {
        match instance {}
    }
}

impl<const PLUMBING: bool> HmacProvider for EmptyCal<PLUMBING> {
    type Algorithm = NoAlgorithms;
    type Key = NoAlgorithms;
    type State = NoAlgorithms;
    type Output = NoAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::State {
        match key {}
    }

    fn update(&mut self, state: &mut Self::State, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::State) -> Self::Output {
        match state {}
    }
}

impl<const PLUMBING: bool> AeadProvider for EmptyCal<PLUMBING> {
    type Algorithm = NoAlgorithms;
    type Key = NoAlgorithms;
    type Tag = NoAlgorithms;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match alg {}
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _aad: impl AadGenerator,
    ) -> Self::Tag {
        match *key {}
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: impl AadGenerator,
    ) -> Result<(), DecryptionFailed> {
        match *key {}
    }
}

impl<const PLUMBING: bool> DhProvider for EmptyCal<PLUMBING> {
    type Algorithm = NoAlgorithms;
    type VisibleSecretKey = NoAlgorithms;
    type SecretKey = NoAlgorithms;
    type PublicKey = NoAlgorithms;
    type SharedSecret = NoAlgorithms;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {}
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        _public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, IncompatibleKeys> {
        match *private {}
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match *private {}
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, PLUMBING> {
        match *secret {};
        &[]
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, PLUMBING> {
        match *secretkey {};
        &[]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        _secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, dh::ImportError> {
        match alg {}
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, PLUMBING> {
        match *public {};
        &[]
    }
    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        _data: &[u8],
    ) -> Result<Self::PublicKey, dh::ImportError> {
        match alg {}
    }
}

impl plumbing::Plumbing for EmptyCal<true> {}

impl plumbing::hash::Hash for EmptyCal<true> {}

impl plumbing::hash::Sha2Short for EmptyCal<true> {
    const SUPPORTED: bool = false;
    const SEND_PADDING: bool = false;
    const FIRST_CHUNK_SIZE: usize = 0;
    const UPDATE_MULTICHUNK: bool = false;

    type State = NoAlgorithms;

    fn init(&mut self, _variant: plumbing::hash::Sha2ShortVariant) -> Self::State {
        panic!("user disregarded SUPPORTED=false")
    }

    fn update(&mut self, instance: &mut Self::State, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::State, _last_chunk: &[u8], _target: &mut [u8]) {
        match instance {}
    }
}

impl<C: plumbing::ec::Curve> plumbing::ec::EcPrimitives<C> for EmptyCal<true> {
    const HAS_MULTIPLY_SCALAR_POINT: bool = false;

    type Scalar = NoAlgorithms;
    type Point = NoAlgorithms;

    fn multiply_scalar_point(&mut self, a: &Self::Scalar, _b: &Self::Point) -> Self::Point {
        match *a {}
    }
}

/// Type which an implementation of [`Cal`] can use when it implements no algorithm for a
/// particular provider.
///
/// This type is uninhabited and can stand in for all of the `Algorithm` associated types as well
/// as state and result types.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NoAlgorithms {}

impl AeadAlgorithm for NoAlgorithms {
    fn key_length(&self) -> usize {
        match *self {}
    }

    fn tag_length(&self) -> usize {
        match *self {}
    }

    fn nonce_length(&self) -> usize {
        match *self {}
    }
}

impl HashAlgorithm for NoAlgorithms {
    fn len(&self) -> usize {
        match *self {}
    }
}

impl HmacAlgorithm for NoAlgorithms {
    const MAX_LEN: usize = 0;

    type MaxLenBuf = [u8; 0];

    fn len(&self) -> usize {
        match *self {}
    }
}

impl AsRef<[u8]> for NoAlgorithms {
    fn as_ref(&self) -> &[u8] {
        match *self {}
    }
}

impl DhAlgorithm for NoAlgorithms {
    fn output_length(&self) -> usize {
        match *self {}
    }
}
