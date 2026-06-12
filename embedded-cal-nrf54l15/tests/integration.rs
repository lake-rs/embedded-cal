#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software_demo::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = embedded_cal_nrf54l15::Nrf54l15Cal;
}
struct TestState {
    cal: embedded_cal_software_demo::Extender<ImplementSha256Short>,
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal::Cal;

    #[init]
    fn init() -> super::TestState {
        // FIXME: How to make sure there is a exclusive reference for CRACEN_S?
        let base =
            embedded_cal_nrf54l15::Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S);

        let cal = embedded_cal_software_demo::Extender::<ImplementSha256Short>::new(base);

        super::TestState { cal }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HmacProvider>::Algorithm,
        >();
        testvectors::test_hmac_sha256(&mut state.cal);
    }

    #[test]
    fn test_hkdf_sha256(state: &mut super::TestState) {
        testvectors::test_hkdf_sha256(&mut state.cal);
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        embedded_cal::test_tryrng(&mut state.cal);
    }

    #[test]
    fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_128(state.cal.aead());
    }

    #[test]
    fn test_aead_aesccm_16_64_256(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_256(state.cal.aead());
    }
}
