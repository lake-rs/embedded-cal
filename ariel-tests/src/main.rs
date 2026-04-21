#![no_main]
#![no_std]

use ariel_os::debug::{ExitCode, exit, log::info};

mod configured_cal;

#[ariel_os::task(autostart, peripherals)]
async fn main(peripherals: configured_cal::Peripherals) {
    info!(
        "Running tests for embedded-cal on a {} board.",
        ariel_os::buildinfo::BOARD
    );

    let mut cal = configured_cal::cal(peripherals);

    info!(
        "Running on a Cal instance of type {}",
        core::any::type_name_of_val(&cal)
    );

    info!("Running SHA256 tests");
    // FIXME: This'll need a tests_of_val() or similar so we capture the type in a generic
    // embedded_cal::test_hash_algorithm_sha256::<
    //     <RustcryptoCal as embedded_cal::HashProvider>::Algorithm,
    // >();
    testvectors::test_hash_algorithm_sha256(&mut cal);

    info!("All tests done.");
    exit(ExitCode::SUCCESS);
}
