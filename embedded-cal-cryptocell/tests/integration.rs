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
