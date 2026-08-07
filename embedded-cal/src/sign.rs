// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Digital signature creation and verification
pub trait SignProvider {
    type Algorithm: SignAlgorithm;

    /// A secret key that is intended to be exported
    /// See [`DhProvider::VisibleSecretKey`][super::DhProvider::VisibleSecretKey]
    /// for the reason of splitting this from [`SecretKey`][Self::SecretKey]
    type VisibleSecretKey: Sized + Into<Self::SecretKey>;
    type SecretKey: Sized;
    type PublicKey: Sized;
    type Signature: Sized;

    /// Generates a secret key that is intended to be exported / shared (e.g. to be persisted
    /// across program executions).
    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey;

    /// Generates a secret key.
    fn generate(&mut self, alg: Self::Algorithm) -> Self::SecretKey {
        self.generate_visible(alg).into()
    }

    /// Exposes a private key's key data bytes.
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, Self>;

    /// Imports a public key in the inverse operation of
    /// [`.export_secretkey_bytes()`][Self::export_secretkey_bytes()].
    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, super::ImportError>;

    /// Exposes a public key's key data bytes.
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, Self>;

    /// Imports a public key in the inverse operation of
    /// [`.export_publickey_bytes()`][Self::export_publickey_bytes()].
    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, super::ImportError>;

    /// Produces the public key corresponding to a private key.
    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey;

    /// Exposes a signature's bytes.
    ///
    /// For ECDSA, this is the raw `r || s` representation.
    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, Self>;
    /// Inverse operation of [`.export_signature_bytes()`][Self::export_signature_bytes()].
    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, super::ImportError>;

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid>;
}

/// Error indicating that a signature did not verify against the given public key and message.
#[derive(Debug)]
pub struct SignatureInvalid;

impl core::fmt::Display for SignatureInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("signature is not valid for the given public key and message")
    }
}

impl core::error::Error for SignatureInvalid {}

/// A signature algorithm.
pub trait SignAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Length of signatures produced by keys of this algorithm.
    fn signature_length(&self) -> usize;

    /// Selects a signature algorithm from its COSE "alg" number.
    ///
    /// The algorithm number comes from the ["COSE Algorithms"
    /// registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) maintained by IANA.
    fn from_cose_number(_alg: impl Into<i128>) -> Option<Self> {
        None
    }
}
