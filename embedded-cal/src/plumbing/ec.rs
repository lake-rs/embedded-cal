// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Traits describing EC (Elliptic Curve) primitives that can be hardware accelerated.

pub trait Ec {
    /// The longest slice length ever usable with scalar import / export from any of the
    /// primitives.
    const MAX_SCALAR_LENGTH: usize;

    type PrimitivesP256: EcPrimitives<P256>;
    type PrimitivesP384: EcPrimitives<P384>;
    type PrimitivesX25519: EcPrimitives<X25519>;
    type PrimitivesX448: EcPrimitives<X448>;

    fn p256(&mut self) -> &mut Self::PrimitivesP256;
    fn p384(&mut self) -> &mut Self::PrimitivesP384;
    fn x25519(&mut self) -> &mut Self::PrimitivesX25519;
    fn x448(&mut self) -> &mut Self::PrimitivesX448;
}

/// The P-256 [`Scalar`][EcPrimitives::Scalar] type of an [`Ec`] implementation.
pub type P256ScalarOf<T> = <<T as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Scalar;
/// The P-256 [`Point`][EcPrimitives::Point] type of an [`Ec`] implementation.
pub type P256PointOf<T> = <<T as Ec>::PrimitivesP256 as EcPrimitives<P256>>::Point;
/// The P-384 [`Scalar`][EcPrimitives::Scalar] type of an [`Ec`] implementation.
pub type P384ScalarOf<T> = <<T as Ec>::PrimitivesP384 as EcPrimitives<P384>>::Scalar;
/// The P-384 [`Point`][EcPrimitives::Point] type of an [`Ec`] implementation.
pub type P384PointOf<T> = <<T as Ec>::PrimitivesP384 as EcPrimitives<P384>>::Point;

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
    /// Indicates whether [`Self::multiply_scalar_point()`] is available (otherwise it will likely
    /// panic).
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

    /// Loads byte data into a scalar from the curve's native format.
    ///
    /// # Notes
    ///
    /// This is a slice because we can't have associated constants influence array lengths yet.
    ///
    /// We can't pull in an associated constant to make it take an array (and depending on the
    /// invariants needed for the curves beyond clamping, it would then still be a faillible
    /// operation).
    ///
    /// One option for getting earlier errors would be to take a reference to a length-generic
    /// array and const-assert on the lengths (causing not a type but at least a conditional
    /// compilation error), but that will need some testing w/rt ergonomics.
    fn import_scalar_bytes(&mut self, scalar: &[u8]) -> Result<Self::Scalar, crate::ImportError>;

    /// Constructs a point from two scalars.
    ///
    /// # Requirements and panics
    ///
    /// It is the caller's responsibility to pass in coordinates that are on the curve. The
    /// implementation may perform an extra check, and may panic if that constraint is violated.
    ///
    /// # Open issues (FIXME)
    ///
    /// When all relevant operations happen only on the X coordinate (i.e., on X25519/X448),
    /// implementations currently ignore the `y` coordinate. This will be addressed when later
    /// there is the implementation experience with ECDSA using the backend. (Potential resolutions
    /// include making that coordinate optional, making a type-level distinction for a
    /// `YScalar`, or having a dedicated plumbing back-end for OKP keys).
    fn point(&mut self, x: Self::Scalar, y: Self::Scalar) -> Self::Point;

    /// Inverse function of [`Self::import_scalar_bytes()`].
    ///
    /// # Notes
    ///
    /// Can we alter this to not depend on C? And if so, does that rule out any optimizations?
    fn export_scalar_bytes<'s>(
        &mut self,
        scalar: &'s Self::Scalar,
    ) -> impl AsRef<[u8]> + use<'s, C, Self>;

    /// Accesses the first coordinate of a point.
    fn x_coord(&mut self, point: &Self::Point) -> Self::Scalar;
    /// Accesses the second coordinate of a point.
    ///
    /// This may (preferably const) panic for curves where that makes no sense (because all
    /// operations run on X coordinates only).
    fn y_coord(&mut self, point: &Self::Point) -> Self::Scalar;
}

/// Type-value trait to parametrize [`EcPrimitives`] over.
// FIXME should we seal this? (Not for safety reasons, just so we can extend it easily.)
pub trait Curve {}

pub struct P256(());
impl Curve for P256 {}
pub struct P384(());
impl Curve for P384 {}
pub struct X25519(());
impl Curve for X25519 {}
pub struct X448(());
impl Curve for X448 {}
