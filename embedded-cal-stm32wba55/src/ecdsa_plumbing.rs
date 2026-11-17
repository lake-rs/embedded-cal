// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::SignatureInvalid;
use embedded_cal::plumbing::ec::P256;
use embedded_cal::plumbing::ecdsa::EcdsaPrimitives;
use embedded_cal::util::p256::{P256_ORDER_BYTES, bytes_to_words, words_to_bytes};
use embedded_cal::util::{in_scalar_range, random_scalar};
use zeroize::Zeroizing;

use super::Stm32wba55Cal;
use super::dh_plumbing::{StmPoint, StmScalar};

/// Number of fresh nonces tried before signing gives up.
const SIGN_MAX_ATTEMPTS: usize = 4;

impl embedded_cal::plumbing::ecdsa::Ecdsa for Stm32wba55Cal {}

impl EcdsaPrimitives<P256> for Stm32wba55Cal {
    const HAS_ECDSA: bool = true;

    fn ecdsa_generate(&mut self) -> StmScalar {
        let d = Zeroizing::new(random_scalar(self, &P256_ORDER_BYTES));
        StmScalar(bytes_to_words(&d))
    }

    fn ecdsa_sign(&mut self, d: &StmScalar, h: &[u8]) -> (StmScalar, StmScalar) {
        let h: &[u8; 32] = h.try_into().expect("P-256 digests are 32 bytes");
        // `StmScalar` wipes itself on drop, and `k` is wrapped in `Zeroizing` so its stack copies
        // are wiped on every exit path. A leaked `k` reveals `d` from one signature.
        let d = &d.0;
        // An out-of-range `d` makes every PKA attempt fail, which would otherwise look like an
        // endless run of unusable nonces.
        assert!(
            in_scalar_range(&Zeroizing::new(words_to_bytes(d)), &P256_ORDER_BYTES),
            "ECDSA private scalar not in 1..n"
        );
        let h = bytes_to_words(h);
        // A genuinely unusable nonce (r or s reducing to zero) has probability about 2^-256, so
        // repeated failures mean the hardware is faulty rather than unlucky.
        for _ in 0..SIGN_MAX_ATTEMPTS {
            let k_bytes = Zeroizing::new(random_scalar(self, &P256_ORDER_BYTES));
            let k = Zeroizing::new(bytes_to_words(&k_bytes));
            if let Some((r, s)) = self.pka_ecdsa_sign(d, &k, &h) {
                return (StmScalar(r), StmScalar(s));
            }
        }
        panic!("PKA ECDSA sign failed repeatedly");
    }

    fn ecdsa_verify(
        &mut self,
        q: &StmPoint,
        h: &[u8],
        r: &StmScalar,
        s: &StmScalar,
    ) -> Result<(), SignatureInvalid> {
        let h: &[u8; 32] = h.try_into().expect("P-256 digests are 32 bytes");
        self.pka_ecdsa_verify(&q.x.0, &q.y.0, &bytes_to_words(h), &r.0, &s.0)
    }
}
