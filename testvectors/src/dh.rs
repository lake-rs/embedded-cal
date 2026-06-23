// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

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
