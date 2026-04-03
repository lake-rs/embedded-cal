#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = embedded_cal_stm32wba55::Stm32wba55Cal;
}

struct TestState {
    cal: embedded_cal_software::Extender<ImplementSha256Short>,
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal_stm32wba55::Stm32wba55Cal;
    #[init]
    fn init() -> super::TestState {
        let base = embedded_cal_stm32wba55::Stm32wba55Cal::new(
            stm32_metapac::HASH,
            stm32_metapac::RCC,
            stm32_metapac::RNG,
        );

        let cal = embedded_cal_software::Extender::<ImplementSha256Short>::new(base);
        super::TestState { cal }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <Stm32wba55Cal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        embedded_cal::test_tryrng(&mut state.cal);
    }
}
