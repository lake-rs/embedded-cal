// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]
#![no_main]

use defmt_rtt as _;
use nrf_pac as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software_demo::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    const IMPLEMENT_SHA2SHORT_PLUMBING: bool = false;
    type Base = embedded_cal_cryptocell::CryptoCellCal;
}
struct TestState {
    // Having the option to take it and return it is useful until everything is also implemented
    // blanket on &mut T
    cal: Option<embedded_cal_cryptocell::CryptoCellCal>,
}

fn with_extender(
    state: &mut TestState,
    cb: impl FnOnce(&mut embedded_cal_software_demo::Extender<ImplementSha256Short>),
) {
    let mut cal = embedded_cal_software_demo::Extender::<ImplementSha256Short>::new(
        state.cal.take().unwrap(),
    );

    cb(&mut cal);

    state.cal = Some(cal.destruct());
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal::Cal;
    use embedded_cal_cryptocell::CryptoCellCal;
    use embedded_cal_testvectors as testvectors;

    #[init]
    fn init() -> super::TestState {
        let base = embedded_cal_cryptocell::CryptoCellCal::new(
            embedded_cal_cryptocell::Peripherals::all(),
        );

        super::TestState { cal: Some(base) }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HashProvider>::Algorithm,
        >();

        super::with_extender(state, testvectors::test_hash_algorithm_sha256);
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HmacProvider>::Algorithm,
        >();
        super::with_extender(state, testvectors::test_hmac_sha256);
    }

    #[test]
    fn test_hkdf_sha256(state: &mut super::TestState) {
        super::with_extender(state, testvectors::test_hkdf_sha256);
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        testvectors::rng::test(&mut state.cal.as_mut().unwrap());
    }

    #[test]
    fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
        testvectors::aead::aes_ccm::test_16_64_128(state.cal.as_mut().unwrap().aead());
    }

    /// AAD around 0xFF00 bytes, where CCM switches from the 2-byte to the 6-byte length encoding
    /// (RFC 3610 2.2). The AAD is a 256-byte pattern repeated from flash. The expected values were
    /// computed with pyca/cryptography's AESCCM.
    #[test]
    fn test_aead_aesccm_long_aad(state: &mut super::TestState) {
        use embedded_cal::{AeadAlgorithm as _, AeadProvider};

        static PATTERN: [u8; 256] = {
            let mut p = [0u8; 256];
            let mut i = 0;
            while i < 256 {
                p[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
                i += 1;
            }
            p
        };
        const KEY: [u8; 16] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ];
        const NONCE: [u8; 13] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
        ];
        const PLAINTEXT: &[u8] = b"long AAD test";
        const CIPHERTEXT: [u8; 13] = [
            0x46, 0x41, 0x58, 0x70, 0xee, 0x5a, 0x69, 0x4a, 0x33, 0x8c, 0xc9, 0x95, 0xcd,
        ];
        // (AAD length, tag)
        const CASES: [(usize, [u8; 8]); 3] = [
            (0xFEFF, [0xfd, 0xb3, 0x5d, 0xed, 0x77, 0x83, 0x21, 0x6d]),
            (0xFF00, [0xe5, 0xa3, 0xbc, 0x7e, 0x88, 0xac, 0x15, 0x4f]),
            (0x1_0000, [0x8a, 0x9e, 0xc4, 0xe4, 0x0e, 0xb5, 0x7e, 0x38]),
        ];

        let cal = state.cal.as_mut().unwrap();
        let alg = <CryptoCellCal as AeadProvider>::Algorithm::from_cose_number(10).unwrap();
        let key = cal.load_from_keydata(alg, &KEY);
        for (aad_len, tag) in CASES {
            let mut chunks: [&[u8]; 256] = [&[]; 256];
            for (i, chunk) in chunks.iter_mut().enumerate() {
                let start = i * PATTERN.len();
                *chunk = &PATTERN[..aad_len.saturating_sub(start).min(PATTERN.len())];
            }
            let aad: &[&[u8]] = &chunks;

            let mut buf = [0u8; 13];
            buf.copy_from_slice(PLAINTEXT);
            let out = cal.encrypt_in_place(&key, &NONCE, &mut buf, aad);
            assert_eq!(buf, CIPHERTEXT, "ciphertext, AAD length {aad_len:#x}");
            assert_eq!(out.as_ref(), tag, "tag, AAD length {aad_len:#x}");

            cal.decrypt_in_place(&key, &NONCE, &mut buf, &tag, aad)
                .expect("decryption");
            assert_eq!(buf, PLAINTEXT, "plaintext, AAD length {aad_len:#x}");
        }
    }

    #[test]
    fn test_aead_aesccm_16_64_256(state: &mut super::TestState) {
        #[cfg(feature = "nrf5340")]
        testvectors::aead::aes_ccm::test_16_64_256(state.cal.as_mut().unwrap().aead());
        // The CryptoCell-310 AES engine only supports 128-bit keys: the algorithm must not be
        // offered.
        #[cfg(feature = "nrf52840")]
        {
            use embedded_cal::AeadAlgorithm;
            let _ = state;
            assert!(
                <CryptoCellCal as embedded_cal::AeadProvider>::Algorithm::from_cose_number(11)
                    .is_none()
            );
        }
    }

    #[test]
    fn test_dh_ecdh_p256(state: &mut super::TestState) {
        embedded_cal::test_dh_algorithm_ecdh_p256::<CryptoCellCal>();
        for v in testvectors::dh::RFC5903_P256 {
            v.test_with(state.cal.as_mut().unwrap().dh());
        }
    }

    #[test]
    fn test_dh_x25519(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X25519 {
            v.test_with(state.cal.as_mut().unwrap().dh());
        }
    }

    #[test]
    fn test_dh_x448(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X448 {
            v.test_with(state.cal.as_mut().unwrap().dh());
        }
    }

    #[test]
    fn test_ec_plumbing_p256(state: &mut super::TestState) {
        for v in testvectors::dh::RFC5903_P256 {
            v.test_plumbing_p256(state.cal.as_mut().unwrap());
        }
    }

    #[test]
    fn test_ec_plumbing_x25519(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X25519 {
            v.test_plumbing_x25519(state.cal.as_mut().unwrap());
        }
    }

    #[test]
    fn test_ec_plumbing_x448(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X448 {
            v.test_plumbing_x448(state.cal.as_mut().unwrap());
        }
    }

    #[test]
    fn test_sign_ecdsa_p256(state: &mut super::TestState) {
        for v in testvectors::sign::ECDSA_P256 {
            v.test_with(state.cal.as_mut().unwrap());
        }
    }

    #[test]
    fn test_verify_ecdsa_p256(state: &mut super::TestState) {
        for v in testvectors::sign::ECDSA_P256_SIGVER {
            v.test_with(state.cal.as_mut().unwrap());
        }
    }

    #[test]
    fn test_sign_roundtrip_ecdsa_p256(state: &mut super::TestState) {
        use embedded_cal::{SignAlgorithm, SignProvider};

        // The known-answer vectors only exercise verification; this covers signing. (The CAL is
        // its own SignProvider, so its methods are called directly.)
        let cal: &mut CryptoCellCal = state.cal.as_mut().unwrap();
        let alg = <CryptoCellCal as SignProvider>::Algorithm::from_cose_number(-7).unwrap();
        let secret = cal.generate(alg.clone());
        let public = cal.public_key(&secret);
        let message = b"embedded-cal on CryptoCell";

        let signature = SignProvider::sign(cal, &secret, message);
        assert_eq!(cal.export_signature_bytes(&signature).as_ref().len(), 64);
        cal.verify(&public, message, &signature)
            .expect("fresh signature did not verify");
        assert!(
            cal.verify(&public, b"another message", &signature).is_err(),
            "signature verified for a different message"
        );

        // Round trip through the byte representations.
        let public_bytes: [u8; 33] = cal
            .export_publickey_bytes(&public)
            .as_ref()
            .try_into()
            .unwrap();
        let public = cal
            .import_publickey_bytes(alg.clone(), &public_bytes)
            .unwrap();
        let signature_bytes: [u8; 64] = cal
            .export_signature_bytes(&signature)
            .as_ref()
            .try_into()
            .unwrap();
        let signature = cal.import_signature_bytes(alg, &signature_bytes).unwrap();
        cal.verify(&public, message, &signature)
            .expect("re-imported signature did not verify");
    }

    #[test]
    fn test_demo(state: &mut super::TestState) {
        embedded_cal_examples::show_examples(state.cal.as_mut().unwrap());
    }
}
