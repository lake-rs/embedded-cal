// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use embedded_cal::plumbing::ec::*;

impl Ec for Stm32wba55Cal {
    const MAX_SCALAR_LENGTH: usize = 32;

    type PrimitivesP256 = Self;
    fn p256(&mut self) -> &mut Self::PrimitivesP256 {
        self
    }

    type PrimitivesX25519 = embedded_cal::empty::EmptyCal;
    fn x25519(&mut self) -> &mut Self::PrimitivesX25519 {
        &mut self.empty
    }

    type PrimitivesX448 = embedded_cal::empty::EmptyCal;
    fn x448(&mut self) -> &mut Self::PrimitivesX448 {
        &mut self.empty
    }
}

impl EcPrimitives<P256> for Stm32wba55Cal {
    const HAS_MULTIPLY_SCALAR_POINT: bool = true;
    type Scalar = StmScalar;
    type Point = StmPoint;

    fn multiply_scalar_point(&mut self, a: &Self::Scalar, b: &Self::Point) -> Self::Point {
        let (x, y) = self.pka_ecc_mult(&a.0, &b.x.0, &b.y.0);
        StmPoint {
            x: StmScalar(x),
            y: StmScalar(y),
        }
    }

    fn import_scalar_bytes(
        &mut self,
        scalar: &[u8],
    ) -> Result<Self::Scalar, embedded_cal::ImportError> {
        Ok(StmScalar(embedded_cal::util::p256::bytes_to_words(
            scalar.try_into().map_err(|_| embedded_cal::ImportError)?,
        )))
    }

    fn point(&mut self, x: Self::Scalar, y: Self::Scalar) -> Self::Point {
        StmPoint { x, y }
    }

    fn export_scalar_bytes<'s>(&mut self, scalar: &'s Self::Scalar) -> impl AsRef<[u8]> + use<'s> {
        // The scalar may be a private key, so the exported copy is wiped on drop as well.
        zeroize::Zeroizing::new(embedded_cal::util::p256::words_to_bytes(&scalar.0))
    }

    fn x_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        point.x.clone()
    }

    fn y_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        point.y.clone()
    }
}

// Wiped on drop: besides ECDH operands, this holds ECDSA private keys.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct StmScalar(pub(crate) [u32; 8]);

// Fails to compile if `StmScalar` stops wiping itself on drop.
const _: () = {
    const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<StmScalar>();
};

pub struct StmPoint {
    pub(crate) x: StmScalar,
    pub(crate) y: StmScalar,
}
