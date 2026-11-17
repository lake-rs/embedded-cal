// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Tools helpful in implementing `embedded-cal`

pub mod aesccm;
pub mod montgomery;
pub mod p256;
pub mod p384;

/// A 2-variant generic enum, useful for writing implementations that provide some own variants on
/// those passed on directly to a base.
///
/// It implements various traits depending on the own and base trait; currently, just as `AsRef`.
///
/// # Caveats
///
/// **Do not use this to** extend own enums, as those will become types with their fixed layout that
/// might easily use the very same discriminator field as the underlying type, and thus defeat
/// possible optimizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<Own, Base> {
    Own(Own),
    Direct(Base),
}

impl<T: ?Sized, Own: AsRef<T>, Base: AsRef<T>> AsRef<T> for Either<Own, Base> {
    fn as_ref(&self) -> &T {
        match self {
            Either::Own(o) => o.as_ref(),
            Either::Direct(d) => d.as_ref(),
        }
    }
}
