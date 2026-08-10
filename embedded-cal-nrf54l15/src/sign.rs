// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{SignatureInvalid, plumbing::ecdsa::EcdsaP256};

impl EcdsaP256 for super::Nrf54l15Cal {
    fn p256_mult(
        &mut self,
        scalar: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        self.cracen_p256_mult(scalar, px, py)
    }

    fn ecdsa_sign(
        &mut self,
        d: &[u8; 32],
        k: &[u8; 32],
        h: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 32])> {
        self.cracen_ecdsa_sign(d, k, h)
    }

    fn ecdsa_verify(
        &mut self,
        qx: &[u8; 32],
        qy: &[u8; 32],
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<(), SignatureInvalid> {
        self.cracen_ecdsa_verify(qx, qy, h, r, s)
    }
}
