// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::plumbing::ec::{Curve, Ec, EcPrimitives, P256, X448, X25519};
use hexlit::hex;

pub struct EccVector {
    // extend as needed
    ecdh_curve: i8,
    alice_private: &'static [u8],
    alice_public: &'static [u8],
    bob_private: &'static [u8],
    bob_public: &'static [u8],
    shared_secret: &'static [u8],
}

impl EccVector {
    /// Runs the test vector by the Cal implementation.
    ///
    /// Panics if either the algorithm is not supported, or either direction of running DH does not
    /// result in the expected shared secret.
    pub fn test_with<C: embedded_cal::Cal>(&self, cal: &mut C) {
        use embedded_cal::{DhAlgorithm, DhProvider};

        let cal = cal.dh();

        let alg = <C::DhProvider as DhProvider>::Algorithm::from_cose_ecdh(self.ecdh_curve)
            .expect("algorithm not supported by CAL");
        let alice_private = cal
            .import_secretkey_bytes(alg.clone(), self.alice_private)
            .expect("failed to load Alice's secret key")
            .into();
        let alice_public = cal.public_key(&alice_private);
        let bob_private = cal
            .import_secretkey_bytes(alg, self.bob_private)
            .expect("failed to load Bob's secret key")
            .into();
        let bob_public = cal.public_key(&bob_private);

        assert_eq!(
            cal.export_publickey_bytes(&alice_public).as_ref(),
            self.alice_public,
            "Alice's public key not exported as expected"
        );
        assert_eq!(
            cal.export_publickey_bytes(&bob_public).as_ref(),
            self.bob_public,
            "Bob's public key not exported as expected"
        );

        let shared_ab = cal
            .shared_secret(&alice_private, &bob_public)
            .expect("keys should be compatible");
        assert_eq!(
            cal.raw_secret_bytes(&shared_ab).as_ref(),
            self.shared_secret
        );
        let shared_ba = cal
            .shared_secret(&bob_private, &alice_public)
            .expect("keys should be compatible");
        assert_eq!(
            cal.raw_secret_bytes(&shared_ba).as_ref(),
            self.shared_secret
        );
    }
}

// Test vectors from Section 6.1 of RFC7748
// <https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1>
pub const RFC7748_X25519: &[EccVector] = &[EccVector {
    ecdh_curve: 4,
    alice_private: &hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    alice_public: &hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    bob_private: &hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    bob_public: &hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
    shared_secret: &hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
}];

// Test vectors from Section 6.2 of RFC7748
// <https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.2>
pub const RFC7748_X448: &[EccVector] = &[EccVector {
    ecdh_curve: 5,
    alice_private: &hex!(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
    ),
    alice_public: &hex!(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
    ),
    bob_private: &hex!(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
    ),
    bob_public: &hex!(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    ),
    shared_secret: &hex!(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    ),
}];

pub const RFC5903_P256: &[EccVector] = &[EccVector {
    ecdh_curve: 1,
    // "initiator"
    alice_private: &hex!("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433"),
    alice_public: &hex!("DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180"),
    // "responder"
    bob_private: &hex!("C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53"),
    bob_public: &hex!("D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63"),
    shared_secret: &hex!("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE"),
}];

/// Base point u-coordinate of X25519 (RFC 7748 section 4.1), little-endian.
const X25519_BASE_U: [u8; 32] = {
    let mut u = [0; 32];
    u[0] = 9;
    u
};

/// Base point u-coordinate of X448 (RFC 7748 section 4.2), little-endian.
const X448_BASE_U: [u8; 56] = {
    let mut u = [0; 56];
    u[0] = 5;
    u
};

/// Tests that exercise the [EC plumbing][embedded_cal::plumbing::ec] directly
impl EccVector {
    pub fn test_plumbing_p256<E: Ec>(&self, ec: &mut E) {
        assert_eq!(self.ecdh_curve, 1, "vector is not a P-256 vector");
        const {
            assert!(
                <E::PrimitivesP256 as EcPrimitives<P256>>::HAS_MULTIPLY_SCALAR_POINT,
                "back-end does not implement P-256 scalar multiplication"
            )
        };
        let p256 = ec.p256();

        for (private, public) in [
            (self.alice_private, self.alice_public),
            (self.bob_private, self.bob_public),
        ] {
            // Scalar import/export round trip, independent of any multiplication
            let d = p256
                .import_scalar_bytes(private)
                .expect("test vector scalar rejected");
            assert_eq!(
                p256.export_scalar_bytes(&d).as_ref(),
                private,
                "P-256 scalar did not survive an import/export round trip"
            );

            // d * G == the public key. Both generator coordinates are known constants, so this
            // needs no point decompression.
            let base = base_point_p256(p256);
            let computed = p256.multiply_scalar_point(&d, &base);
            let computed_x = p256.x_coord(&computed);
            assert_eq!(
                p256.export_scalar_bytes(&computed_x).as_ref(),
                public,
                "P-256 public key does not match the test vector"
            );
        }

        // d_alice * Q_bob == Z == d_bob * Q_alice.
        for (private, peer) in [
            (self.alice_private, self.bob_public),
            (self.bob_private, self.alice_public),
        ] {
            let d = p256
                .import_scalar_bytes(private)
                .expect("test vector scalar rejected");
            let peer = point_from_compact_p256(p256, peer);
            let shared = p256.multiply_scalar_point(&d, &peer);
            let shared_x = p256.x_coord(&shared);
            assert_eq!(
                p256.export_scalar_bytes(&shared_x).as_ref(),
                self.shared_secret,
                "P-256 shared secret does not match the test vector"
            );
        }
    }

    pub fn test_plumbing_x25519<E: Ec>(&self, ec: &mut E) {
        assert_eq!(self.ecdh_curve, 4, "vector is not an X25519 vector");
        const {
            assert!(
                <E::PrimitivesX25519 as EcPrimitives<X25519>>::HAS_MULTIPLY_SCALAR_POINT,
                "back-end does not implement X25519 scalar multiplication"
            )
        };
        let x25519 = ec.x25519();

        for (private, public) in [
            (self.alice_private, self.alice_public),
            (self.bob_private, self.bob_public),
        ] {
            let mut scalar: [u8; 32] = private.try_into().expect("vector has a 32 byte scalar");
            embedded_cal::montgomery::clamp_x25519(&mut scalar);
            let d = x25519
                .import_scalar_bytes(&scalar)
                .expect("test vector scalar rejected");
            assert_eq!(
                x25519.export_scalar_bytes(&d).as_ref(),
                scalar,
                "X25519 scalar did not survive an import/export round trip"
            );

            let base = montgomery_point(x25519, &X25519_BASE_U);
            let computed = x25519.multiply_scalar_point(&d, &base);
            let computed_u = x25519.x_coord(&computed);
            assert_eq!(
                x25519.export_scalar_bytes(&computed_u).as_ref(),
                public,
                "X25519 public key does not match the test vector"
            );
        }

        for (private, peer) in [
            (self.alice_private, self.bob_public),
            (self.bob_private, self.alice_public),
        ] {
            let mut scalar: [u8; 32] = private.try_into().expect("vector has a 32 byte scalar");
            embedded_cal::montgomery::clamp_x25519(&mut scalar);
            let d = x25519
                .import_scalar_bytes(&scalar)
                .expect("test vector scalar rejected");

            let mut peer_u: [u8; 32] = peer.try_into().expect("vector has a 32 byte u coordinate");
            embedded_cal::montgomery::mask_u_x25519(&mut peer_u);
            let peer = montgomery_point(x25519, &peer_u);

            let shared = x25519.multiply_scalar_point(&d, &peer);
            let shared_u = x25519.x_coord(&shared);
            assert_eq!(
                x25519.export_scalar_bytes(&shared_u).as_ref(),
                self.shared_secret,
                "X25519 shared secret does not match the test vector"
            );
        }
    }

    pub fn test_plumbing_x448<E: Ec>(&self, ec: &mut E) {
        assert_eq!(self.ecdh_curve, 5, "vector is not an X448 vector");
        const {
            assert!(
                <E::PrimitivesX448 as EcPrimitives<X448>>::HAS_MULTIPLY_SCALAR_POINT,
                "back-end does not implement X448 scalar multiplication"
            )
        };
        let x448 = ec.x448();

        for (private, public) in [
            (self.alice_private, self.alice_public),
            (self.bob_private, self.bob_public),
        ] {
            let mut scalar: [u8; 56] = private.try_into().expect("vector has a 56 byte scalar");
            embedded_cal::montgomery::clamp_x448(&mut scalar);
            let d = x448
                .import_scalar_bytes(&scalar)
                .expect("test vector scalar rejected");
            assert_eq!(
                x448.export_scalar_bytes(&d).as_ref(),
                scalar,
                "X448 scalar did not survive an import/export round trip"
            );

            let base = montgomery_point(x448, &X448_BASE_U);
            let computed = x448.multiply_scalar_point(&d, &base);
            let computed_u = x448.x_coord(&computed);
            assert_eq!(
                x448.export_scalar_bytes(&computed_u).as_ref(),
                public,
                "X448 public key does not match the test vector"
            );
        }

        for (private, peer) in [
            (self.alice_private, self.bob_public),
            (self.bob_private, self.alice_public),
        ] {
            let mut scalar: [u8; 56] = private.try_into().expect("vector has a 56 byte scalar");
            embedded_cal::montgomery::clamp_x448(&mut scalar);
            let d = x448
                .import_scalar_bytes(&scalar)
                .expect("test vector scalar rejected");
            let peer = montgomery_point(x448, peer);

            let shared = x448.multiply_scalar_point(&d, &peer);
            let shared_u = x448.x_coord(&shared);
            assert_eq!(
                x448.export_scalar_bytes(&shared_u).as_ref(),
                self.shared_secret,
                "X448 shared secret does not match the test vector"
            );
        }
    }
}

/// Builds the P-256 generator as a plumbing point.
fn base_point_p256<P: EcPrimitives<P256>>(p256: &mut P) -> P::Point {
    let x = p256
        .import_scalar_bytes(&embedded_cal::p256::P256_GX_BYTES)
        .expect("generator x is a valid scalar");
    let y = p256
        .import_scalar_bytes(&embedded_cal::p256::P256_GY_BYTES)
        .expect("generator y is a valid scalar");
    p256.point(x, y)
}

/// Builds a P-256 point from its compact (x-only) representation.
fn point_from_compact_p256<P: EcPrimitives<P256>>(p256: &mut P, x: &[u8]) -> P::Point {
    let x: &[u8; 32] = x.try_into().expect("vector has a 32 byte x coordinate");
    let y = embedded_cal::p256::p256_recover_y(x).expect("vector point is on the curve");
    let x = p256
        .import_scalar_bytes(x)
        .expect("test vector coordinate rejected");
    let y = p256
        .import_scalar_bytes(&y)
        .expect("recovered coordinate rejected");
    p256.point(x, y)
}

/// Builds a Montgomery curve point from its u coordinate.
///
/// The `y` coordinate is unused on these curves (see [`EcPrimitives::point()`]), but the interface
/// demands one, so a zero scalar is passed.
fn montgomery_point<C: Curve, P: EcPrimitives<C>>(primitives: &mut P, u: &[u8]) -> P::Point {
    let unused_y = primitives
        .import_scalar_bytes(&[0; 56][..u.len()])
        .expect("zero is a valid scalar");
    let u = primitives
        .import_scalar_bytes(u)
        .expect("test vector u coordinate rejected");
    primitives.point(u, unused_y)
}
