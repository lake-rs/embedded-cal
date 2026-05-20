#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct TestState {
    cal: embedded_cal_stm32wba55::Stm32wba55Cal,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal_stm32wba55::Stm32wba55Cal;

    #[init]
    fn init() -> super::TestState {
        super::TestState {
            cal: Stm32wba55Cal::new(stm32_metapac::HASH, &stm32_metapac::RCC),
        }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <Stm32wba55Cal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <Stm32wba55Cal as embedded_cal::HmacProvider>::Algorithm,
        >();
        testvectors::test_hmac_sha256(&mut state.cal);
    }
}
