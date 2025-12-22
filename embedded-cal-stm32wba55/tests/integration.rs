#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct TestState {
    cal: embedded_cal_stm32wba55::Stm32wba55,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal_stm32wba55::Stm32wba55;
    #[init]
    fn init() -> super::TestState {
        let cal =
            embedded_cal_stm32wba55::Stm32wba55::new(stm32_metapac::HASH, &stm32_metapac::RCC);

        super::TestState { cal }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <Stm32wba55 as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }
}
