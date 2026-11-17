// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Tests that exercise the [ECDSA plumbing][embedded_cal::plumbing::ecdsa] directly, on
//! pre-hashed digests.
//!
//! The vectors were produced with Python's `cryptography` (OpenSSL) from a fixed private key and
//! the digest of `b"sample"` under the curve's COSE hash (SHA-256 for P-256, SHA-384 for P-384).

use embedded_cal::plumbing::{
    ec::{Curve, P256, P384},
    ecdsa::{Ecdsa, EcdsaPrimitives},
};
use embedded_cal::util::{p256, p384};
use hexlit::hex;

/// A known ECDSA key and signature over an already hashed message.
///
/// All values are big-endian; the signature components are as long as the curve's scalars.
pub struct EcdsaPlumbingVector {
    private_key: &'static [u8],
    public_x: &'static [u8],
    public_y: &'static [u8],
    digest: &'static [u8],
    r: &'static [u8],
    s: &'static [u8],
}

pub const P256_PLUMBING: &[EcdsaPlumbingVector] = &[EcdsaPlumbingVector {
    private_key: &hex!("25d9bf7435e7af0750529bb4e0e3d1aa72068a82fcb8f3c15d60d2882cc1ef9e"),
    public_x: &hex!("268678a1c95be53af8d5cb21dccaf504e38431f869b59477ae51b6b988f3db59"),
    public_y: &hex!("800719ce62731b427b4f1fd8c3c0b08725a55432ba3c90051a848e0c1ee05920"),
    digest: &hex!("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"),
    r: &hex!("6f2dbd64b84fe99c49cc52d6d4f76f65a772b400482db8ba86e67a3bfc59d29f"),
    s: &hex!("b9da261f4a8f9f1d89110351e2aad4539543bf582c23c9c35b8ce051302260de"),
}];

pub const P384_PLUMBING: &[EcdsaPlumbingVector] = &[EcdsaPlumbingVector {
    private_key: &hex!(
        "46a6ff364e45ded2b111f8a218f3bf8c2113740c41fc35e10d6838c664fa8b63802cf735c6cc1c530de949f542021a47"
    ),
    public_x: &hex!(
        "bf232c7858177276b40c6f817f25b7a54f2f8d94b29de01a60ace2a4f92f3970ca530ccf82149de58415fd639b1cf1aa"
    ),
    public_y: &hex!(
        "84996d637a4a12c0127501077873cf5f6518824368b101058b58a6b78f6dfec7d2da5c4e9556d8912209a3c30c4aa3bf"
    ),
    digest: &hex!(
        "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe"
    ),
    r: &hex!(
        "7fa2e6adef2de85b4394cf8cc6d78e71f408bee3e1857c7b05a67dd2487cda2e71eec410658d001ef7ae8422941169a8"
    ),
    s: &hex!(
        "242b60f8de83699146d1a775a04a5a531461664c54181825a7b50ab34d831457c1996c32016e193e937aacdee595f2ed"
    ),
}];

impl EcdsaPlumbingVector {
    pub fn test_plumbing_p256<E: Ecdsa>(&self, ec: &mut E) {
        const {
            assert!(
                <E::PrimitivesP256 as EcdsaPrimitives<P256>>::HAS_ECDSA,
                "back-end does not implement P-256 ECDSA"
            )
        };
        self.test_curve(ec.p256(), &p256::P256_GX_BYTES, &p256::P256_GY_BYTES);
    }

    pub fn test_plumbing_p384<E: Ecdsa>(&self, ec: &mut E) {
        const {
            assert!(
                <E::PrimitivesP384 as EcdsaPrimitives<P384>>::HAS_ECDSA,
                "back-end does not implement P-384 ECDSA"
            )
        };
        self.test_curve(ec.p384(), &p384::P384_GX_BYTES, &p384::P384_GY_BYTES);
    }

    /// The actual test, which is the same for every curve.
    fn test_curve<C: Curve, P: EcdsaPrimitives<C>>(&self, p: &mut P, gx: &[u8], gy: &[u8]) {
        let scalar = |p: &mut P, bytes: &[u8]| {
            p.import_scalar_bytes(bytes)
                .expect("test vector scalar rejected")
        };
        let point = |p: &mut P, x: &[u8], y: &[u8]| {
            let x = scalar(p, x);
            let y = scalar(p, y);
            p.point(x, y)
        };
        let base = point(p, gx, gy);
        let q = point(p, self.public_x, self.public_y);

        // The vector's key pair is consistent with this back-end's point multiplication.
        if P::HAS_MULTIPLY_SCALAR_POINT {
            let d = scalar(p, self.private_key);
            let computed = p.multiply_scalar_point(&d, &base);
            let (x, y) = (p.x_coord(&computed), p.y_coord(&computed));
            assert_eq!(p.export_scalar_bytes(&x).as_ref(), self.public_x);
            assert_eq!(p.export_scalar_bytes(&y).as_ref(), self.public_y);
        }

        // The known signature verifies; a different digest or a different signature does not.
        let r = scalar(p, self.r);
        let s = scalar(p, self.s);
        p.ecdsa_verify(&q, self.digest, &r, &s)
            .expect("known-good signature rejected");
        let mut other_digest = [0; 64];
        let other_digest = &mut other_digest[..self.digest.len()];
        other_digest.copy_from_slice(self.digest);
        other_digest[0] ^= 1;
        assert!(
            p.ecdsa_verify(&q, other_digest, &r, &s).is_err(),
            "signature accepted for a different digest"
        );
        assert!(
            p.ecdsa_verify(&q, self.digest, &s, &r).is_err(),
            "signature accepted with r and s swapped"
        );

        // Signing with the known key produces a signature that verifies (and not for another
        // digest). The nonce is random, so the signature itself is not compared.
        let d = scalar(p, self.private_key);
        let (r, s) = p.ecdsa_sign(&d, self.digest);
        p.ecdsa_verify(&q, self.digest, &r, &s)
            .expect("own signature rejected");
        assert!(p.ecdsa_verify(&q, other_digest, &r, &s).is_err());

        // A freshly generated key round-trips too.
        if P::HAS_MULTIPLY_SCALAR_POINT {
            let d = p.ecdsa_generate();
            let q = p.multiply_scalar_point(&d, &base);
            let (r, s) = p.ecdsa_sign(&d, self.digest);
            p.ecdsa_verify(&q, self.digest, &r, &s)
                .expect("signature of generated key rejected");
        }
    }
}
