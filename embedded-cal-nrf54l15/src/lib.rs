#![no_std]
mod descriptor;
mod inner;

use inner::Nrf54l15CalInner;

pub struct DefaultConfig;

impl embedded_cal_software::ExtenderConfig for DefaultConfig {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = Nrf54l15CalInner;
}

pub struct Nrf54l15Cal(embedded_cal_software::Extender<DefaultConfig>);

impl Nrf54l15Cal {
    pub fn new(
        cracen: nrf_pac::cracen::Cracen,
        cracen_core: nrf_pac::cracencore::Cracencore,
    ) -> Self {
        Self(embedded_cal_software::Extender::new(
            Nrf54l15CalInner::new_inner(cracen, cracen_core),
        ))
    }
}

impl embedded_cal_core::Cal for Nrf54l15Cal {}

impl embedded_cal_core::HashProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal_software::HashAlgorithm<DefaultConfig>;
    type HashState = embedded_cal_software::HashState<DefaultConfig>;
    type HashResult = embedded_cal_software::HashResult<DefaultConfig>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        embedded_cal_core::HashProvider::init(&mut self.0, algorithm)
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        embedded_cal_core::HashProvider::update(&mut self.0, instance, data)
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        embedded_cal_core::HashProvider::finalize(&mut self.0, instance)
    }
}

impl embedded_cal_core::HmacProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal_software::HmacAlgorithm;
    type HmacState = embedded_cal_software::HmacState<DefaultConfig>;
    type HmacResult = embedded_cal_software::HmacResult;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
        embedded_cal_core::HmacProvider::init(&mut self.0, algorithm, key)
    }

    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]) {
        embedded_cal_core::HmacProvider::update(&mut self.0, state, data)
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        embedded_cal_core::HmacProvider::finalize(&mut self.0, state)
    }
}
