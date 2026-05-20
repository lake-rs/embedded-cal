#![no_std]
mod inner;

use inner::Stm32wba55CalInner;

pub struct DefaultConfig;

impl embedded_cal_software::ExtenderConfig for DefaultConfig {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = Stm32wba55CalInner;
}

pub struct Stm32wba55Cal(embedded_cal_software::Extender<DefaultConfig>);

impl Stm32wba55Cal {
    pub fn new(hash: stm32_metapac::hash::Hash, rcc: &stm32_metapac::rcc::Rcc) -> Self {
        Self(embedded_cal_software::Extender::new(
            Stm32wba55CalInner::new_inner(hash, rcc),
        ))
    }
}

impl embedded_cal_core::Cal for Stm32wba55Cal {}

impl embedded_cal_core::HashProvider for Stm32wba55Cal {
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

impl embedded_cal_core::HmacProvider for Stm32wba55Cal {
    type Algorithm = inner::HmacAlgorithm;
    type HmacState = inner::HmacState;
    type HmacResult = inner::HmacResult;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
        embedded_cal_core::HmacProvider::init(self.0.base_mut(), algorithm, key)
    }

    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]) {
        embedded_cal_core::HmacProvider::update(self.0.base_mut(), state, data)
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        embedded_cal_core::HmacProvider::finalize(self.0.base_mut(), state)
    }
}
