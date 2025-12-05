#![no_std]
#![no_main]

use embedded_cal_nrf54l15 as _; // memory layout + panic handler

#[cfg(test)]
#[defmt_test::tests]
mod tests {
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[test]
    fn test_hash_algorithm_sha256() {
        let p = nrf54l15_app_pac::Peripherals::take().unwrap();

        let mut cal = embedded_cal_nrf54l15::Nrf54l15Cal::new(p);

        embedded_cal::test_hash_algorithm_sha256::<
            <Nrf54l15Cal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut cal);
    }
}
