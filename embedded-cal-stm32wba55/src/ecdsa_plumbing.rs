// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::SignatureInvalid;
use embedded_cal::util::p256::{P256_ORDER, bytes_to_words, ge, words_to_bytes};
use rand_core::Rng as _;
use zeroize::Zeroizing;

use super::Stm32wba55Cal;
use super::dh_plumbing::{StmPoint, StmScalar};

/// Number of fresh nonces tried before signing gives up.
const SIGN_MAX_ATTEMPTS: usize = 4;

impl Stm32wba55Cal {
    /// Draws a scalar uniformly from `1..n` by rejection sampling.
    ///
    /// The working buffers are wiped on return; the caller owns (and must wipe) the result.
    fn random_p256_scalar(&mut self) -> [u8; 32] {
        let mut scalar = Zeroizing::new([0u8; 32]);
        loop {
            self.fill_bytes(&mut *scalar);
            let w = Zeroizing::new(bytes_to_words(&scalar));
            if *w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                return *scalar;
            }
        }
    }
}

impl embedded_cal::plumbing::ecdsa::Ecdsa for Stm32wba55Cal {
    const SUPPORTED: bool = true;

    fn ecdsa_p256_generate(&mut self) -> StmScalar {
        let d = Zeroizing::new(self.random_p256_scalar());
        StmScalar(bytes_to_words(&d))
    }

    fn ecdsa_p256_sign(&mut self, d: &StmScalar, h: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // `StmScalar` wipes itself on drop, and `k` is wrapped in `Zeroizing` so its stack copies
        // are wiped on every exit path. A leaked `k` reveals `d` from one signature.
        let d = &d.0;
        // An out-of-range `d` makes every PKA attempt fail, which would otherwise look like an
        // endless run of unusable nonces.
        assert!(
            *d != [0u32; 8] && !ge(d, &P256_ORDER),
            "ECDSA private scalar not in 1..n"
        );
        let h = bytes_to_words(h);
        // A genuinely unusable nonce (r or s reducing to zero) has probability about 2^-256, so
        // repeated failures mean the hardware is faulty rather than unlucky.
        for _ in 0..SIGN_MAX_ATTEMPTS {
            let k_bytes = Zeroizing::new(self.random_p256_scalar());
            let k = Zeroizing::new(bytes_to_words(&k_bytes));
            if let Some((r, s)) = self.pka_ecdsa_sign(d, &k, &h) {
                return (words_to_bytes(&r), words_to_bytes(&s));
            }
        }
        panic!("PKA ECDSA sign failed repeatedly");
    }

    fn ecdsa_p256_verify(
        &mut self,
        q: &StmPoint,
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<(), SignatureInvalid> {
        self.pka_ecdsa_verify(
            &q.x.0,
            &q.y.0,
            &bytes_to_words(h),
            &bytes_to_words(r),
            &bytes_to_words(s),
        )
    }
}
