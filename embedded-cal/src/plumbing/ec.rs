// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
// SPDX-License-Identifier: MIT OR Apache-2.0

pub trait Ec {
    type PrimitivesP256: EcPrimitives<P256>;
    type PrimitivesX25519: EcPrimitives<X25519>;
    type PrimitivesX448: EcPrimitives<X448>;

    fn p256(&mut self) -> &mut Self::PrimitivesP256;
    fn x25519(&mut self) -> &mut Self::PrimitivesX25519;
    fn x448(&mut self) -> &mut Self::PrimitivesX448;
}

/// Providers for ECC primitive operations on a given curve.
///
/// Implementations whose back-end uses similar code on various curves can use identical types (or
/// types that only vary by phantom data) as associated types.
///
/// # Clamping
///
/// It is not expected that this trait's types check or perform clamping of RFC7748 operands
/// (called the `decodeScalar…` functions there).
///
/// However, so far, no algorithms depend on no clamping *not* to happen; if an implementation does
/// turn out to to do all of implementing these accelerations, requiring (or performing) clamping
/// and not implementing the higher-level traits directly, we might revisit this requirement after
/// amore thorough survey of applications; then, this trait's requirement might become that the
/// implementation may silently perform or even require clamping of values.
pub trait EcPrimitives<C: Curve> {
    const HAS_MULTIPLY_SCALAR_POINT: bool;

    type Scalar;
    type Point;

    /// Performs a scalar × point multiplication on the curve.
    ///
    /// # Panics
    ///
    /// This may panic when the associated types are independent of `C` (which makes sense for
    /// highly abstracted accelerators) and their runtime curves do not match. (Code that uses this
    /// trait can only even reach this if it explicitly requires that those are identical).
    // Should we offer an "and give the X coordinate only" optimization?
    fn multiply_scalar_point(&mut self, a: &Self::Scalar, b: &Self::Point) -> Self::Point;
}

/// Type-value trait to parametrize [`EcPrimitives`] over.
// FIXME should we seal this? (Not for safety reasons, just so we can extend it easily.)
pub trait Curve {}

pub struct P256(());
impl Curve for P256 {}
pub struct X25519(());
impl Curve for X25519 {}
pub struct X448(());
impl Curve for X448 {}
