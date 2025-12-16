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
        // Safety: These peripherals are taken exactly once during initialization
        // This guarantees exclusive ownership of the underlying registers for the lifetime of the test
        let cracen = unsafe { nrf54l15_app_pac::GlobalCracenS::steal() };
        let cracen_core = unsafe { nrf54l15_app_pac::GlobalCracencoreS::steal() };

        let cal = embedded_cal_nrf54l15::Nrf54l15Cal::new(cracen, cracen_core);

        super::TestState { cal }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <Nrf54l15Cal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_hash_algorithm_sha384(state: &mut super::TestState) {
        testvectors::test_hash_algorithm_sha384(&mut state.cal);
    }

    #[test]
    fn test_hash_algorithm_sha512(state: &mut super::TestState) {
        testvectors::test_hash_algorithm_sha512(&mut state.cal);
    }
}
