//! All the impls of Cal that the libcrux extender does *not* really provide.
//!
//! (This should be small enough to inline back into the top module when
//! <https://github.com/lake-rs/embedded-cal/issues/40> is addressed).

use super::*;

impl<EC: ExtenderConfig> embedded_cal::HmacProvider for Extender<EC> {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type Key = embedded_cal::empty::NoAlgorithms;
    type HmacState = embedded_cal::empty::NoAlgorithms;
    type HmacResult = embedded_cal::empty::NoAlgorithms;

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
