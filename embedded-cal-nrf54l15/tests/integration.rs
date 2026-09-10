// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software_demo::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    const IMPLEMENT_SHA2SHORT_PLUMBING: bool = false;
    type Base = embedded_cal_nrf54l15::Nrf54l15Cal;
}
struct TestState {
    // Having the option to take it and return it is useful until everything is also implemented
    // blanket on &mut T
    cal: Option<embedded_cal_nrf54l15::Nrf54l15Cal>,
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
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[init]
    fn init() -> super::TestState {
        // FIXME: How to make sure there is a exclusive reference for CRACEN_S?
        let base =
            embedded_cal_nrf54l15::Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S);

        super::TestState { cal: Some(base) }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HashProvider>::Algorithm,
        >();

        super::with_extender(state, |cal| testvectors::test_hash_algorithm_sha256(cal));
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HmacProvider>::Algorithm,
        >();
        super::with_extender(state, |cal| testvectors::test_hmac_sha256(cal));
    }

    #[test]
    fn test_hkdf_sha256(state: &mut super::TestState) {
        super::with_extender(state, |cal| testvectors::test_hkdf_sha256(cal));
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        embedded_cal::test_tryrng(&mut state.cal.as_mut().unwrap());
    }

    #[test]
    fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_128(state.cal.as_mut().unwrap().aead());
    }

    #[test]
    fn test_aead_aesccm_16_64_256(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_256(state.cal.as_mut().unwrap().aead());
    }

    #[test]
    fn test_dh_ecdh_p256(state: &mut super::TestState) {
        embedded_cal::test_dh_algorithm_ecdh_p256::<Nrf54l15Cal>();
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
            v.test_plumbing_x25519(state.cal.as_mut().unwrap());
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
}
