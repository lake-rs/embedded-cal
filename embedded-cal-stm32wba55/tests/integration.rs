#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software_demo::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = embedded_cal_stm32wba55::Stm32wba55Cal;
}

struct TestState {
    /// Software-extended CAL used for the SHA-256 hash tests.
    cal: embedded_cal_software_demo::Extender<ImplementSha256Short>,
    /// Raw STM32WBA55 CAL used to exercise the hardware HMAC accelerator directly.
    raw: embedded_cal_stm32wba55::Stm32wba55Cal,
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal_stm32wba55::Stm32wba55Cal;
    #[init]
    fn init() -> super::TestState {
        // stm32_metapac::HASH is a `const`, so it can be used at two sites
        // without conflict; both values alias the same hardware register block.
        // Tests run sequentially so there is no concurrent access.
        let raw = embedded_cal_stm32wba55::Stm32wba55Cal::new(
            stm32_metapac::HASH,
            stm32_metapac::RCC,
            stm32_metapac::RNG,
            stm32_metapac::AES,
        );
        let base = embedded_cal_stm32wba55::Stm32wba55Cal::new(
            stm32_metapac::HASH,
            stm32_metapac::RCC,
            stm32_metapac::RNG,
            stm32_metapac::AES,
        );

        let cal = embedded_cal_software_demo::Extender::<ImplementSha256Short>::new(base);
        super::TestState { cal, raw }
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
        // Runs directly against the hardware HMAC accelerator (MODE=1 in HASH_CR).
        testvectors::test_hmac_sha256(&mut state.raw);
    }

    #[test]
    fn test_hkdf_sha256(state: &mut super::TestState) {
        testvectors::test_hkdf_sha256(&mut state.raw);
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        embedded_cal::test_tryrng(&mut state.cal);
    }

    #[test]
    fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_128(&mut state.raw);
    }
}
