#![no_main]
#![no_std]

use defmt_rtt as _; // global logger
use panic_probe as _;

#[cfg(test)]
#[defmt_test::tests]
mod unit_tests {
    use defmt::assert;

    #[test]
    fn it_works() {
        assert!(true)
    }
}
