// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use embedded_cal::plumbing::ec::*;

impl Ec for Stm32wba55Cal {
    type PrimitivesP256 = Self;
    fn p256(&mut self) -> &mut Self::PrimitivesP256 {
        self
    }

    type PrimitivesX25519 = embedded_cal::empty::EmptyCal<true>;
    fn x25519(&mut self) -> &mut Self::PrimitivesX25519 {
        &mut self.empty
    }

    type PrimitivesX448 = embedded_cal::empty::EmptyCal<true>;
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
}

pub struct StmScalar([u32; 8]);
pub struct StmPoint {
    x: StmScalar,
    y: StmScalar,
}
