// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Traits by which hardare primitives can be made available that are not in themselves high-level
//! primitives.
//!
//! On the long run, this trait will be split for independent versioning, allowing the high-level
//! traits to remain stable even when the underlying primitives need to be extended to support more
//! exotic hardware constraints.

pub mod ec;
pub mod ecdsa;
pub mod hash;

/// Sum of all traits that a hardware accelerator can provide.
///
/// To avoid that users need to do type-level configuration depending on what the back-end
/// provides, all these traits have a `const SUPPORTED: bool`: If this is false (which will be
/// default once the `associated_type_defaults` feature lands), all other values are ignored, and
/// all functions can use the provided panicking implementations.
pub trait Plumbing: hash::Hash + ec::Ec + ecdsa::Ecdsa {}
