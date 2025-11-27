#![no_std]
#![no_main]

use embedded_cal_nrf54l15 as _; // memory layout + panic handler

#[defmt_test::tests]
mod tests {
    use defmt::assert;

    #[test]
    fn it_works() {
        assert!(true)
    }
}
