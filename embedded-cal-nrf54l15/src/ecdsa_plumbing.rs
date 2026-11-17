// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::SignatureInvalid;
use embedded_cal::plumbing::ec::P256;
use embedded_cal::plumbing::ecdsa::EcdsaPrimitives;
use embedded_cal::util::p256::{P256_ORDER, bytes_to_words, ge};
use rand_core::Rng as _;
use zeroize::Zeroizing;

use super::Nrf54l15Cal;
use super::dh_plumbing::{NrfPoint, NrfScalar};

/// Number of fresh nonces tried before signing gives up.
const SIGN_MAX_ATTEMPTS: usize = 4;

impl Nrf54l15Cal {
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

impl embedded_cal::plumbing::ecdsa::Ecdsa for Nrf54l15Cal {}

impl EcdsaPrimitives<P256> for Nrf54l15Cal {
    const HAS_ECDSA: bool = true;

    fn ecdsa_generate(&mut self) -> NrfScalar<P256> {
        self.random_p256_scalar().into()
    }

    fn ecdsa_sign(&mut self, d: &NrfScalar<P256>, h: &[u8]) -> (NrfScalar<P256>, NrfScalar<P256>) {
        let h: &[u8; 32] = h.try_into().expect("P-256 digests are 32 bytes");
        let d: &[u8; 32] = d.as_ref();
        // An out-of-range `d` makes every PKE attempt fail, which would otherwise look like an
        // endless run of unusable nonces.
        let d_words = Zeroizing::new(bytes_to_words(d));
        assert!(
            *d_words != [0u32; 8] && !ge(&d_words, &P256_ORDER),
            "ECDSA private scalar not in 1..n"
        );
        // A genuinely unusable nonce (r or s reducing to zero) has probability about 2^-256, so
        // repeated failures mean the hardware is faulty rather than unlucky.
        for _ in 0..SIGN_MAX_ATTEMPTS {
            // Wiped on every exit path; a leaked `k` reveals `d` from one signature.
            let k = Zeroizing::new(self.random_p256_scalar());
            if let Some((r, s)) = self.cracen_ecdsa_sign(d, &k, h) {
                return (r.into(), s.into());
            }
        }
        panic!("CRACEN ECDSA sign failed repeatedly");
    }

    fn ecdsa_verify(
        &mut self,
        q: &NrfPoint<P256>,
        h: &[u8],
        r: &NrfScalar<P256>,
        s: &NrfScalar<P256>,
    ) -> Result<(), SignatureInvalid> {
        let h: &[u8; 32] = h.try_into().expect("P-256 digests are 32 bytes");
        self.cracen_ecdsa_verify(q.x.as_ref(), q.y.as_ref(), h, r.as_ref(), s.as_ref())
    }
}
