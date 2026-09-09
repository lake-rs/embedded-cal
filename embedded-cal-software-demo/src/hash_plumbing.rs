// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Implementations of SHA2 plumbing
//!
//! Currently, this is only passing through.

use super::{Extender, ExtenderConfig};
use embedded_cal::plumbing::hash::Sha2Short;

impl<EC: ExtenderConfig> Sha2Short for Extender<EC> {
    const SUPPORTED: bool = <EC::Base as embedded_cal::plumbing::hash::Sha2Short>::SUPPORTED;
    const SEND_PADDING: bool = <EC::Base as embedded_cal::plumbing::hash::Sha2Short>::SEND_PADDING;
    const FIRST_CHUNK_SIZE: usize =
        <EC::Base as embedded_cal::plumbing::hash::Sha2Short>::FIRST_CHUNK_SIZE;
    const UPDATE_MULTICHUNK: bool =
        <EC::Base as embedded_cal::plumbing::hash::Sha2Short>::UPDATE_MULTICHUNK;

    type State = <EC::Base as embedded_cal::plumbing::hash::Sha2Short>::State;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        self.0.init(variant)
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        self.0.update(instance, data)
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        self.0.finalize(instance, last_chunk, target)
    }
}
