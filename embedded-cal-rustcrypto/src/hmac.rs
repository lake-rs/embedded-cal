// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::RustcryptoCal;
use embedded_cal::empty::NoAlgorithms;
use embedded_cal::*;

impl HmacProvider for RustcryptoCal {
    type Algorithm = NoAlgorithms;
    type Key = NoAlgorithms;
    type State = NoAlgorithms;
    type Output = NoAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::State {
        match key {}
    }

    fn update(&mut self, state: &mut Self::State, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::State) -> Self::Output {
        match state {}
    }
}
