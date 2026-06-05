use super::RustcryptoCal;
use embedded_cal::empty::NoAlgorithms;
use embedded_cal::*;

impl HmacProvider for RustcryptoCal {
    type Algorithm = NoAlgorithms;
    type Key = NoAlgorithms;
    type HmacState = NoAlgorithms;
    type HmacResult = NoAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::HmacState {
        match key {}
    }

    fn update(&mut self, state: &mut Self::HmacState, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        match state {}
    }
}
