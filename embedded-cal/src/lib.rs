// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! embedded-cal is a family of interface traits around cryptography, primarily [`Cal`].
//!
//! *Users of the trait* can implement their high-level cryptographic protocol implementation
//! libraries or applications on top of the trait, and leverage hardware acceleration available on
//! some platforms, without being tied to a particular implementation of the algorithms or a
//! aprticular acceleration module.
//!
//! *Providers of the trait* can be software implementations, specific hardware platforms, or
//! embedded operating systems that provide whichever acceleration or algorithms are configured for
//! a givens build.
//!
//! Neither the users or nor the providers are generally implemented in this crate; however, being
//! the centerpiece of the embedded-cal ecosystem, this documentation points to some noteworthy
//! implementations outside the crate.
//!
//! ## How to use this crate
//!
//! ### … as a user
//!
//! When a library you use requires you to pass in an implementation of [`Cal`], their functions
//! are generic over implementations of [`Cal`].
//!
//! Depending on the system you use the library on, you can obtain a suitable instance to pass in
//! from:
//!
//! * Your operating system.
//!   * On embedded systems, this can be provided explicitly by the RTOS (e.g. work in progress in
//!     Ariel OS and RIOT OS).
//!   * On `std` systems, you can use software based implementations, which (while fundamentally
//!     composable) generally offer a feature for ready-to-use construction (e.g.
//!     [`embedded_cal_libcrux::Standalone::standalone()`](https://docs.rs/embedded-cal-libcrux/latest/embedded_cal_libcrux/type.Standalone.html#method.standalone)
//!     or
//!     [`embedded_cal_rustcrypto::Standalone::standalone()`](https://docs.rs/embedded-cal-rustcrypto/latest/embedded_cal_rustcrypto/type.Standalone.html#method.standalone).
//! * When developing on bare metal, an implementation such as
//! [`embedded-cal-nrf54l15`](https://docs.rs/embedded-cal-nrf54l15/latest/embedded_cal_nrf54l15/struct.Nrf54l15Cal.html)
//! can be constructed from the underlying hardware registers, and later augmented with software
//! layers.
//!
//! Examples of these are in
//! [`embedded-cal-examples/src/bin/demo.rs`](https://github.com/lake-rs/embedded-cal/blob/main/embedded-cal-examples/src/bin/demo.rs)
//! -- depending on the components selected by features, the `Cal` instance is constructed through
//! a standalone constructor or by composition.
//!
//! ### … as a high-level library author
//!
//! When writing a library, be generic over `Cal` implementations.
//!
//! Where possible, it is recommended to take short-lived references to a `Cal`, because this
//! enables users to go with a lock-free exclusive version where that is an advantage.
//!
//! An example of this is in
//! [`embedded-cal-examples/src/lib.rs`](https://github.com/lake-rs/embedded-cal/blob/main/embedded-cal-examples/src/lib.rs):
//! Some of the operations work from a selection of algorithms for agility,
//! some pick fixed algorithm (and fail if it is unsupported; with future Rust versions this can
//! [become a build time failure](https://github.com/lake-rs/embedded-cal/issues/144)),
//!
//! ### … when wrapping hardware
//!
//! Most parts of the [`Cal`] trait are optional to implement, in the sense that supporting no
//! algorithms is easy. (This is the reason why rather than having a single trait, there is an
//! [`Cal::AeadProvider`] iand [`.aead()`][Cal::aead()] accessor: If your hardware can not do it,
//! just don't provide it.
//!
//! In particular, for many aspects (list growing), there are "plumbing" traits you can implement
//! instead. For example, for SHA2, implement
//! [`plumbing::hash::Sha2Short`] and set [`SUPPORTED =
//! true`][plumbing::hash::Sha2Short::SUPPORTED]. While this does not
//! immediately give the users access to the algorithms, a higher-up wrapper can pick up the parts
//! and fill in the gaps. This way, edge-case prone buffer handling can be done by more carefully
//! vetted components rather than being repetitively implemented.
//!
//! ### … as an embedded RTOS maintainer
//!
//! Provide an easy single type implementing [`Cal`]. Configuration should happen outside of the
//! RTOS, typically in system-wide build configuration. By default, it is recommended to build from
//! whichever accelerated type is available for the hardware, and use
//! [`embedded-cal-libcrux`](https://docs.rs/embedded-cal-nrf54l15/latest/embedded_cal_nrf54l15/struct.Nrf54l15Cal.html)
//! to fill gaps.
//!
//! On many systems, that type needs to be a singleton and can not be shared (e.g. because it needs
//! exclusive access to some registers).
//!
//! On systems where mutex-style access is widespread, provide a mutex based implementation that
//! can be shared / cloned easily, so that libraries that can not do everything in short-lived
//! operations can be given something to work with. This API can be enabled conditionally based on
//! whether any user in the current build requests it.
//!
//! It is recommended to also have an accessor for short-time access available unconditionally. If
//! the mutex based API is requested, this merely hands out another copy of the shared instance;
//! otherwise, it can use a simpler run-time (or even build-time) check.
//!
//! ## Distinguishing properties and related work
//!
//! The interfaces of this crate are geared towards *cryptographic agility*: An application should
//! not need to be changed in order to support a larger set of hash functions or elliptic curves.
//! This is aligned with how higher-level cryptographic systems such as COSE or TLS work:
//! algorithms are negotiated rather than built into the protocol. In this, embedded-cal is
//! distinct from many rustcrypto traits such as [`aead`](https://docs.rs/aead/latest/aead/) or
//! [`digest`](https://docs.rs/digest/latest/digest/), through which generic application code gets
//! monomorphized onto a concrete algorithm.
//!
//! The crates focus on the *Embedded Rust ecosystem*, which includes bare metal and RTOS
//! applications. It is `no_std`, and does not use dynamic allocation in general. In this,
//! embedded-cal is distinct from the otherwise similar [PSA Crypto
//! API](https://arm-software.github.io/psa-api/crypto/) (which uses C embedded idioms).
//!
//! Implementations of embedded-cal are *composable*: Rather than having to select a single
//! provider of cryptographic tools, it allows picking suitable parts. For example, a software
//! implementation can be composed from the OS's source of randomness and the [libcrux software
//! implementation](https://crates.io/crates/embedded-cal-libcrux); on embedded hardware, there is
//! typically one layer of what the hardware can do, augmented by a software layer that fills gaps
//! (e.g. when the hardware accelerates elliptic curves primitives, and the software then make a
//! full DH key establishment out of it). Also, different algorithms can be served by different
//! components.
//!
//! The library is designed *with resident secrets in mind* (event though currently, no
//! implementations provide that): Keys are never required to be visible to the user, by virtue of
//! using associated types in many places. This way, implementations based on secure elements can
//! use either encapsulated keys or key slot handles.
#![no_std]

pub mod empty;
pub mod util;

mod aead;
mod dh;
mod error;
mod hash;
mod hkdf;
mod hmac;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use aead::{AadGenerator, AeadAlgorithm, AeadProvider, DecryptionFailed};
pub use dh::{
    DhAlgorithm, DhProvider, IncompatibleKeys, test_dh_algorithm_ecdh_p256, test_dh_selftest,
};
pub use error::ImportError;
pub use hash::{HashAlgorithm, HashProvider, test_hash_algorithm_sha256};
pub use hkdf::{HkdfError, HkdfProvider};
pub use hmac::{HmacAlgorithm, HmacProvider, test_hmac_algorithm_hmacsha256};

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
///
/// For example, [`AeadAlgorithmOf<C>`][accessor::AeadAlgorithmOf] is a shorthand way of writing
/// `<<C as Cal>::AeadProvider as AeadProvider>::Algorithm`, which would often be required because
/// associated type trait requirements are not automatically made available.
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
