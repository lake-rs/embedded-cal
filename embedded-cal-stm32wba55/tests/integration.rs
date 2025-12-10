#![no_std]
#![no_main]

use embedded_cal_stm32wba55 as _; // memory layout + panic handler

struct TestState {
    cal: embedded_cal_stm32wba55::Stm32wba55,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal_stm32wba55::Stm32wba55;

    #[test]
    fn test_empty() {
        assert!(true)
    }

    // #[init]
    // fn init() -> super::TestState {
    //     let p = stm32wba::stm32wba55::Peripherals::take().unwrap();

    //     let cal = embedded_cal_stm32wba55::Stm32wba55::new(p);

    //     super::TestState { cal }
    // }

    // #[test]
    // fn test_hash_algorithm_sha256(state: &mut super::TestState) {
    //     embedded_cal::test_hash_algorithm_sha256::<
    //         <Stm32wba55 as embedded_cal::HashProvider>::Algorithm,
    //     >();
    //     testvectors::test_hash_algorithm_sha256(&mut state.cal);
    // }

    // #[test]
    // fn test_hash_algorithm_sha384(state: &mut super::TestState) {
    //     testvectors::test_hash_algorithm_sha384(&mut state.cal);
    // }

    // #[test]
    // fn test_hash_algorithm_sha512(state: &mut super::TestState) {
    //     testvectors::test_hash_algorithm_sha512(&mut state.cal);
    // }
}
