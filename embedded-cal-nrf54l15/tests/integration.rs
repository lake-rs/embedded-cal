#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct TestState {
    cal: embedded_cal_nrf54l15::Nrf54l15Cal,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[init]
    fn init() -> super::TestState {
        // FIXME: How to make sure there is a exclusive reference for CRACEN_S?
        super::TestState {
            cal: Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S),
        }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <Nrf54l15Cal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <Nrf54l15Cal as embedded_cal::HmacProvider>::Algorithm,
        >();
        testvectors::test_hmac_sha256(&mut state.cal);
    }
}
