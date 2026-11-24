// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Implementation of plumbing for nRF5340 (CryptoCell-312).
//!
//! In this module we try out a strategy where all primitives are the same layout but diferent
//! types, exploring how well code deduplication works: Goal would be that all the conversion
//! functions are neatly deduplicated, whereas the multiplication just doesn't have too much in
//! common.
//!
//! (Other strategies to be explored are using distinct types altogehter, and using a single type
//! with run-time annotations).
//!
//! # Future development
//!
//! Once the basics work, optimization against needless register spilling would be neat. (That
//! might require the use of pinning, or limited primitive creation).
//!
//! # Layout strategy demo
//!
//! The observation underlying the typed-but-otherwise-identical primitive associated types is that
//! this code has very simple assembly output:
//!
// Ignoring because doctests expect some infrastructure; ```no_run alone doens't suffice.
//! ```ignore
//! use core::marker::PhantomData;
//!
//! const MAX_LEN: usize = 10;
//!
//! trait UnimportantDetails {
//!     const LEN: usize;
//! }
//!
//! struct A;
//! struct B;
//!
//! impl UnimportantDetails for A {
//!     const LEN: usize = 3;
//! }
//! impl UnimportantDetails for B {
//!         const LEN: usize = 8;
//! }
//!
//! struct DataSimpleTypeVaries<T: UnimportantDetails> {
//!     data: [u8; MAX_LEN],
//!     phantom: PhantomData<T>,
//! }
//!
//! enum Variations {
//!     A(DataSimpleTypeVaries<A>),
//!     B(DataSimpleTypeVaries<B>),
//! }
//!
//! #[unsafe(no_mangle)]
//! pub fn get_all(v: &Variations) -> &[u8; MAX_LEN] {
//!     match v {
//!         Variations::A(d) => &d.data,
//!         Variations::B(d) => &d.data,
//!     }
//! }
//!
//!
//! #[unsafe(no_mangle)]
//! pub fn get_specific(v: &Variations) -> &[u8] {
//!     match v {
//!         Variations::A(d) => &d.data[..A::LEN],
//!         Variations::B(d) => &d.data[..B::LEN],
//!     }
//! }
//! ```
//!
//! which leads to the very simple ASM:
//!
//! ```asm
//! get_all:
//!     leaq    1(%rdi), %rax
//!     retq
//!
//! get_specific:
//!     movzbl  (%rdi), %eax
//!     leaq    (%rax,%rax,4), %rdx
//!     addq    $3, %rdx
//!     leaq    1(%rdi), %rax
//!     retq
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::*;
use core::marker::PhantomData;
use embedded_cal::plumbing::ec::*;

impl Ec for Nrf5340Cal {
    const MAX_SCALAR_LENGTH: usize = 56;

    type PrimitivesP256 = Self;
    type PrimitivesX25519 = Self;
    type PrimitivesX448 = Self;

    fn p256(&mut self) -> &mut Self::PrimitivesP256 {
        self
    }
    fn x25519(&mut self) -> &mut Self::PrimitivesX25519 {
        self
    }
    fn x448(&mut self) -> &mut Self::PrimitivesX448 {
        self
    }
}

pub(crate) trait NrfCurve: Curve {
    const SCALAR_SIZE: usize;

    fn multiply_scalar_point(
        cal: &mut Nrf5340Cal,
        a: &NrfScalar<Self>,
        b: &NrfPoint<Self>,
    ) -> NrfPoint<Self>;
}

impl NrfCurve for P256 {
    const SCALAR_SIZE: usize = 32;

    fn multiply_scalar_point(
        cal: &mut Nrf5340Cal,
        a: &NrfScalar<Self>,
        b: &NrfPoint<Self>,
    ) -> NrfPoint<Self> {
        let (x, y) = cal.p256_mul(&a.into(), &(&b.x).into(), &(&b.y).into());
        NrfPoint {
            x: x.into(),
            y: y.into(),
        }
    }
}

impl NrfCurve for X25519 {
    const SCALAR_SIZE: usize = 32;

    fn multiply_scalar_point(
        cal: &mut Nrf5340Cal,
        a: &NrfScalar<Self>,
        b: &NrfPoint<Self>,
    ) -> NrfPoint<Self> {
        let x = cal.x25519_mul(&a.into(), &(&b.x).into());
        NrfPoint {
            x: x.into(),
            y: [0; _].into(),
        }
    }
}

impl NrfCurve for X448 {
    const SCALAR_SIZE: usize = 56;

    fn multiply_scalar_point(
        cal: &mut Nrf5340Cal,
        a: &NrfScalar<Self>,
        b: &NrfPoint<Self>,
    ) -> NrfPoint<Self> {
        let x = cal.x448_mul(&a.into(), &(&b.x).into());
        NrfPoint {
            x: x.into(),
            y: [0; _].into(),
        }
    }
}

impl<C: NrfCurve> EcPrimitives<C> for Nrf5340Cal {
    const HAS_MULTIPLY_SCALAR_POINT: bool = true;
    type Scalar = NrfScalar<C>;
    type Point = NrfPoint<C>;

    fn multiply_scalar_point(&mut self, a: &Self::Scalar, b: &Self::Point) -> Self::Point {
        C::multiply_scalar_point(self, a, b)
    }

    fn point(&mut self, x: Self::Scalar, y: Self::Scalar) -> Self::Point {
        NrfPoint { x, y }
    }

    fn import_scalar_bytes(
        &mut self,
        scalar: &[u8],
    ) -> Result<Self::Scalar, embedded_cal::ImportError> {
        if scalar.len() != C::SCALAR_SIZE {
            return Err(embedded_cal::ImportError);
        }
        let mut data = [0; _];
        data[..scalar.len()].copy_from_slice(scalar);
        Ok(NrfScalar {
            data,
            phantom: PhantomData,
        })
    }

    fn export_scalar_bytes<'s>(
        &mut self,
        scalar: &'s Self::Scalar,
    ) -> impl AsRef<[u8]> + use<'s, C> {
        &scalar.data[..C::SCALAR_SIZE]
    }

    fn x_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        NrfScalar {
            data: point.x.data,
            phantom: point.x.phantom,
        }
    }

    fn y_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        NrfScalar {
            data: point.y.data,
            phantom: point.y.phantom,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NrfScalar<C: ?Sized> {
    data: [u8; Nrf5340Cal::MAX_SCALAR_LENGTH],
    #[zeroize(skip)]
    phantom: PhantomData<C>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NrfPoint<C: ?Sized> {
    // This doubles as the `u` coordinate for RFC7748 curves.
    x: NrfScalar<C>,
    // This is not used in RFC7748 curves.
    y: NrfScalar<C>,
}

// FIXME: While const generics can't do that, let's macro over this rather than repeat all over
const _: () = assert!(32 <= Nrf5340Cal::MAX_SCALAR_LENGTH);
impl From<[u8; 32]> for NrfScalar<P256> {
    fn from(value: [u8; 32]) -> Self {
        let mut data = [0; _];
        *data.first_chunk_mut().expect("const asserted") = value;
        NrfScalar {
            data,
            phantom: PhantomData,
        }
    }
}
impl<'a> From<&'a NrfScalar<P256>> for [u8; 32] {
    fn from(value: &'a NrfScalar<P256>) -> Self {
        *value.data.first_chunk().expect("const asserted")
    }
}
impl AsRef<[u8; 32]> for NrfScalar<P256> {
    fn as_ref(&self) -> &[u8; 32] {
        self.data.first_chunk().expect("const asserted")
    }
}
const _: () = assert!(32 <= Nrf5340Cal::MAX_SCALAR_LENGTH);
impl From<[u8; 32]> for NrfScalar<X25519> {
    fn from(value: [u8; 32]) -> Self {
        let mut data = [0; _];
        *data.first_chunk_mut().expect("const asserted") = value;
        NrfScalar {
            data,
            phantom: PhantomData,
        }
    }
}
impl<'a> From<&'a NrfScalar<X25519>> for [u8; 32] {
    fn from(value: &'a NrfScalar<X25519>) -> Self {
        *value.data.first_chunk().expect("const asserted")
    }
}
impl AsRef<[u8; 32]> for NrfScalar<X25519> {
    fn as_ref(&self) -> &[u8; 32] {
        self.data.first_chunk().expect("const asserted")
    }
}
const _: () = assert!(56 <= Nrf5340Cal::MAX_SCALAR_LENGTH);
impl From<[u8; 56]> for NrfScalar<X448> {
    fn from(value: [u8; 56]) -> Self {
        let mut data = [0; _];
        *data.first_chunk_mut().expect("const asserted") = value;
        NrfScalar {
            data,
            phantom: PhantomData,
        }
    }
}
impl<'a> From<&'a NrfScalar<X448>> for [u8; 56] {
    fn from(value: &'a NrfScalar<X448>) -> Self {
        *value.data.first_chunk().expect("const asserted")
    }
}
impl AsRef<[u8; 56]> for NrfScalar<X448> {
    fn as_ref(&self) -> &[u8; 56] {
        self.data.first_chunk().expect("const asserted")
    }
}
