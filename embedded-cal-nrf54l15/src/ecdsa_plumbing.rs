// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::SignatureInvalid;
use embedded_cal::plumbing::ec::{P256, P384};
use embedded_cal::plumbing::ecdsa::EcdsaPrimitives;
use embedded_cal::util::{in_scalar_range, p256, p384};
use nrf_pac::cracencore::vals::Selcurve;
use rand_core::Rng as _;
use zeroize::Zeroizing;

use super::Nrf54l15Cal;
use super::dh_plumbing::{NrfPoint, NrfScalar};

/// Number of fresh nonces tried before signing gives up.
const SIGN_MAX_ATTEMPTS: usize = 4;

impl Nrf54l15Cal {
    /// Draws an `N` byte scalar uniformly from `1..n` by rejection sampling, for the big-endian
    /// curve order `n`.
    ///
    /// The working buffer is wiped on return; the caller owns (and must wipe) the result.
    fn random_scalar<const N: usize>(&mut self, n: &[u8; N]) -> [u8; N] {
        let mut scalar = Zeroizing::new([0u8; N]);
        loop {
            self.fill_bytes(&mut *scalar);
            if in_scalar_range(&scalar, n) {
                return *scalar;
            }
        }
    }

    /// ECDSA signing with `N` byte operands on `selcurve` (whose order is `n`), shared by all
    /// curves.
    fn ecdsa_sign_on<const N: usize>(
        &mut self,
        selcurve: Selcurve,
        n: &[u8; N],
        d: &[u8; N],
        h: &[u8],
    ) -> ([u8; N], [u8; N]) {
        let h: &[u8; N] = h
            .try_into()
            .expect("digest length does not match the curve");
        // An out-of-range `d` makes every PKE attempt fail, which would otherwise look like an
        // endless run of unusable nonces.
        assert!(in_scalar_range(d, n), "ECDSA private scalar not in 1..n");
        // A genuinely unusable nonce (r or s reducing to zero) has probability about 2^-256 (or
        // less), so repeated failures mean the hardware is faulty rather than unlucky.
        for _ in 0..SIGN_MAX_ATTEMPTS {
            // Wiped on every exit path; a leaked `k` reveals `d` from one signature.
            let k = Zeroizing::new(self.random_scalar(n));
            if let Some(signature) = self.cracen_ecdsa_sign(selcurve, d, &k, h) {
                return signature;
            }
        }
        panic!("CRACEN ECDSA sign failed repeatedly");
    }
}

impl embedded_cal::plumbing::ecdsa::Ecdsa for Nrf54l15Cal {}

impl EcdsaPrimitives<P256> for Nrf54l15Cal {
    const HAS_ECDSA: bool = true;

    fn ecdsa_generate(&mut self) -> NrfScalar<P256> {
        self.random_scalar(&p256::P256_ORDER_BYTES).into()
    }

    fn ecdsa_sign(&mut self, d: &NrfScalar<P256>, h: &[u8]) -> (NrfScalar<P256>, NrfScalar<P256>) {
        let (r, s) = self.ecdsa_sign_on(Selcurve::P256, &p256::P256_ORDER_BYTES, d.as_ref(), h);
        (r.into(), s.into())
    }

    fn ecdsa_verify(
        &mut self,
        q: &NrfPoint<P256>,
        h: &[u8],
        r: &NrfScalar<P256>,
        s: &NrfScalar<P256>,
    ) -> Result<(), SignatureInvalid> {
        let h = h.try_into().expect("P-256 digests are 32 bytes");
        self.cracen_ecdsa_verify(
            Selcurve::P256,
            q.x.as_ref(),
            q.y.as_ref(),
            h,
            r.as_ref(),
            s.as_ref(),
        )
    }
}

impl EcdsaPrimitives<P384> for Nrf54l15Cal {
    const HAS_ECDSA: bool = true;

    fn ecdsa_generate(&mut self) -> NrfScalar<P384> {
        self.random_scalar(&p384::P384_ORDER_BYTES).into()
    }

    fn ecdsa_sign(&mut self, d: &NrfScalar<P384>, h: &[u8]) -> (NrfScalar<P384>, NrfScalar<P384>) {
        let (r, s) = self.ecdsa_sign_on(Selcurve::P384, &p384::P384_ORDER_BYTES, d.as_ref(), h);
        (r.into(), s.into())
    }

    fn ecdsa_verify(
        &mut self,
        q: &NrfPoint<P384>,
        h: &[u8],
        r: &NrfScalar<P384>,
        s: &NrfScalar<P384>,
    ) -> Result<(), SignatureInvalid> {
        let h = h.try_into().expect("P-384 digests are 48 bytes");
        self.cracen_ecdsa_verify(
            Selcurve::P384,
            q.x.as_ref(),
            q.y.as_ref(),
            h,
            r.as_ref(),
            s.as_ref(),
        )
    }
}
