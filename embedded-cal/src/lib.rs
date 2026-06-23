// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]

pub mod empty;
pub mod p256;
pub mod util;

mod aead;
mod dh;
mod hash;
mod hkdf;
mod hmac;
mod rng;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use aead::{
    AadGenerator, AeadAlgorithm, AeadProvider, DecryptionFailed, build_b0,
    test_aead_algorithm_aesccm_16_64_128,
};
pub use dh::{
    DhAlgorithm, DhProvider, ImportError, IncompatibleKeys, test_dh_algorithm_ecdh_p256,
    test_dh_selftest,
};
pub use hash::{HashAlgorithm, HashProvider, test_hash_algorithm_sha256};
pub use hkdf::{HkdfError, HkdfProvider};
pub use hmac::{HmacAlgorithm, HmacProvider, test_hmac_algorithm_hmacsha256};
pub use rng::test_tryrng;

#[allow(
    type_alias_bounds,
    reason = "makes the intention clearer, and no danger of later incompatibility because the type expansion explicitly requires that C is a Cal"
)]
/// Accessors to the deep associated types of a [`Cal`].
///
/// As associated types often need explicit naming of the trait (even when the trait is in scope),
/// and due to the various Provider traits being associated types, accessing eg. a Cal's AEAD
/// algorithm type is relatively cumbersome.
///
/// This module provides easy `{Interface}{Type}Of` style type aliases for various values of
/// `Interface` and `Type`.
pub mod accessor {
    use super::*;

    pub type AeadProviderOf<C: Cal> = <C as Cal>::AeadProvider;
    pub type AeadAlgorithmOf<C: Cal> = <<C as Cal>::AeadProvider as AeadProvider>::Algorithm;
    pub type AeadKeyOf<C: Cal> = <<C as Cal>::AeadProvider as AeadProvider>::Key;
    pub type AeadTagOf<C: Cal> = <<C as Cal>::AeadProvider as AeadProvider>::Tag;

    pub type DhProviderOf<C: Cal> = <C as Cal>::DhProvider;
    pub type DhAlgorithmOf<C: Cal> = <<C as Cal>::DhProvider as DhProvider>::Algorithm;
    pub type DhVisibleSecretKeyOf<C: Cal> =
        <<C as Cal>::DhProvider as DhProvider>::VisibleSecretKey;
    pub type DhSecretKeyOf<C: Cal> = <<C as Cal>::DhProvider as DhProvider>::SecretKey;
    pub type DhPublicKeyOf<C: Cal> = <<C as Cal>::DhProvider as DhProvider>::PublicKey;
    pub type DhSharedSecretOf<C: Cal> = <<C as Cal>::DhProvider as DhProvider>::SharedSecret;

    pub type HashProviderOf<C: Cal> = <C as Cal>::HashProvider;
    pub type HashAlgorithmOf<C: Cal> = <<C as Cal>::HashProvider as HashProvider>::Algorithm;
    pub type HashStateOf<C: Cal> = <<C as Cal>::HashProvider as HashProvider>::State;
    pub type HashOutputOf<C: Cal> = <<C as Cal>::HashProvider as HashProvider>::Output;

    pub type HmacProviderOf<C: Cal> = <C as Cal>::HmacProvider;
    pub type HmacAlgorithmOf<C: Cal> = <<C as Cal>::HmacProvider as HmacProvider>::Algorithm;
    pub type HmacKeyOf<C: Cal> = <<C as Cal>::HmacProvider as HmacProvider>::Key;
    pub type HmacStateOf<C: Cal> = <<C as Cal>::HmacProvider as HmacProvider>::State;
    pub type HmacOutputOf<C: Cal> = <<C as Cal>::HmacProvider as HmacProvider>::Output;
}

/// Cryptographic abstraction provider that encompasses all features abstracted by the
/// embedded-cal.
///
/// To ease implementation and give better access to its aspects, this does not have a list of
/// supertraits, but rather various associated types and acccessors to them.
///
/// These allow passing on full portions of the feature set between implementations. Common choices
/// for the associated type and the corresponding accessor implementation are:
///
/// * `type XxxProvider = Self` / `self`, when an object does provide that functionality.
/// * `type XxxProvider = Self::Base` / `self.base.xxx()`, when an extender does not touch that
///   functionality at all and merely forwards it to whatever is being extended.
/// * `type XxxProvider = embedded_cal::empty::EmptyCal` / `&mut self.empty`, when a non-extender
///   (typically a hardware module) does not implement something at all.
///
///   Note that to keep the types reasonably simple, the accessors are `fn(&mut Self) -> &mut
///   Self::XxxProvider`, which requires an existing (albeit zero-sized) [`EmptyCal`][empty::EmptyCal],
///   which is most easily provided by adding one as a field to the `Self` struct. (The alternative
///   would be to go through `AsMut` indirections or use lifetime-generic associated types like
///   `type XxxProvider<'t> = &mut Self` / `= Empty`, and that is not only unergonomic, it also
///   hinders restraining them in `where` clauses).
pub trait Cal {
    /// The non-supertrait responsible for key establishment.
    type DhProvider: DhProvider;
    type AeadProvider: AeadProvider;
    type HashProvider: HashProvider;
    type HmacProvider: HmacProvider;

    fn dh(&mut self) -> &mut Self::DhProvider;
    fn aead(&mut self) -> &mut Self::AeadProvider;
    fn hash(&mut self) -> &mut Self::HashProvider;
    fn hmac(&mut self) -> &mut Self::HmacProvider;
}
