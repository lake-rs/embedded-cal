#![no_std]
#![no_main]

use embedded_cal_nrf54l15 as _; // memory layout + panic handler

struct TestState {
    cal: embedded_cal_nrf54l15::Nrf54l15Cal,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[init]
    fn init() -> super::TestState {
        let p = nrf54l15_app_pac::Peripherals::take().unwrap();

        let cal = embedded_cal_nrf54l15::Nrf54l15Cal::new(p);

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
