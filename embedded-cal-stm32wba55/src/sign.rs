// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{
    SignatureInvalid,
    p256::{bytes_to_words, words_to_bytes},
    plumbing::ecdsa::EcdsaP256,
};

impl EcdsaP256 for super::Stm32wba55Cal {
    fn p256_mult(
        &mut self,
        scalar: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let (x, y) = self.pka_ecc_mult(
            &bytes_to_words(scalar),
            &bytes_to_words(px),
            &bytes_to_words(py),
        );
        (words_to_bytes(&x), words_to_bytes(&y))
    }

    fn ecdsa_sign(
        &mut self,
        d: &[u8; 32],
        k: &[u8; 32],
        h: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 32])> {
        self.pka_ecdsa_sign(&bytes_to_words(d), &bytes_to_words(k), &bytes_to_words(h))
            .map(|(x, y)| (words_to_bytes(&x), words_to_bytes(&y)))
    }

    fn ecdsa_verify(
        &mut self,
        qx: &[u8; 32],
        qy: &[u8; 32],
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<(), SignatureInvalid> {
        self.pka_ecdsa_verify(
            &bytes_to_words(qx),
            &bytes_to_words(qy),
            &bytes_to_words(h),
            &bytes_to_words(r),
            &bytes_to_words(s),
        )
    }
}
