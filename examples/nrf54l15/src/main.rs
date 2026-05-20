#![no_std]
#![no_main]

use cortex_m_rt::entry;
use embedded_cal::HashAlgorithm;
use embedded_cal::HashProvider;
use embedded_cal::HmacAlgorithm;
use embedded_cal::HmacProvider;
use embedded_cal_nrf54l15::Nrf54l15Cal;
use embedded_cal_software::{Extender, ExtenderConfig};
use hexlit::hex;
use {defmt_rtt as _, panic_probe as _};

struct Config;

impl ExtenderConfig for Config {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = Nrf54l15Cal;
}

#[entry]
fn main() -> ! {
    let base = Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S);
    let mut cal = Extender::<Config>::new(base);

    defmt::info!("Running SHA-256...");
    sha256(&mut cal);

    defmt::info!("Running HMAC-SHA-256...");
    hmac_sha256(&mut cal);

    // let mut dst = [0u8; 1];
    // cal.try_fill_bytes(&mut dst).unwrap();
    // defmt::info!("{},", dst[0]);

    loop {
        cortex_m::asm::nop();
    }
}

fn sha256(cal: &mut Extender<Config>) {
    let alg = <Extender<Config> as HashProvider>::Algorithm::from_cose_number(-16i32).unwrap();
    // let alg = <Extender<Config> as HashProvider>::Algorithm::from_ni_name("sha-256").unwrap();
    // let alg = <Extender<Config> as HashProvider>::Algorithm::from_ni_id(1).unwrap();

    let result = cal.hash(alg.clone(), b"Hello world");

    defmt::info!("SHA-256: {=[u8]:02x}", result.as_ref());

    assert_eq!(
        result.as_ref(),
        hex!("64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c")
    );

    defmt::info!("Direct hash passed!");

    let mut hash = HashProvider::init(cal, alg);
    HashProvider::update(cal, &mut hash, b"Hello world");
    let result2 = HashProvider::finalize(cal, hash);

    defmt::info!("SHA-256: {=[u8]:02x}", result2.as_ref());

    assert_eq!(
        result2.as_ref(),
        hex!("64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c")
    );

    defmt::info!("Incremental hash passed!");
}

fn hmac_sha256(cal: &mut Nrf54l15Cal) {
    let alg = <Nrf54l15Cal as HmacProvider>::Algorithm::from_cose_number(5i8).unwrap();

    let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let result = cal.hmac(alg.clone(), &key, data);

    defmt::info!("HMAC-SHA-256: {=[u8]:02x}", result.as_ref());

    assert_eq!(
        result.as_ref(),
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    defmt::info!("Direct HMAC passed!");

    let mut state = HmacProvider::init(cal, alg, &key);
    HmacProvider::update(cal, &mut state, &data[..2]);
    HmacProvider::update(cal, &mut state, &data[2..]);
    let result2 = HmacProvider::finalize(cal, state);

    defmt::info!("HMAC-SHA-256: {=[u8]:02x}", result2.as_ref());

    assert_eq!(
        result2.as_ref(),
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    defmt::info!("Incremental HMAC passed!");
}
