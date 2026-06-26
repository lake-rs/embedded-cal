// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use crate::descriptor::{DescriptorChain, Input, Output};

#[derive(Clone)]
pub struct HashState {
    // We could instead make this unconditional and then set state (in init) to 0x6a, 0x09, 0xe6,
    // 0x67, ... (the big-endian version of the SHA256 starting points 0x6a09e667u32), but the
    // hardware has the values, so why not use them.
    state: Option<[u8; 32]>,
}

impl embedded_cal::plumbing::Plumbing for super::Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Hash for super::Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Sha2Short for super::Nrf54l15Cal {
    const SUPPORTED: bool = true;
    const SEND_PADDING: bool = true;
    const FIRST_CHUNK_SIZE: usize = 64;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        match variant {
            embedded_cal::plumbing::hash::Sha2ShortVariant::Sha256 => (),
            // Although really all we need to support it is probably just copying the requested
            // length into the output buffer
            _ => todo!("Unsupported variant"),
        };

        Self::State { state: None }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(64),
            "Chunking requirements laid out in Self::FIRST_CHUNK_SIZE not upheld."
        );

        let mut new_state: [u8; 32] = [0x00; 32];

        let header: [u8; 4] = [0x08, 0x00, 0x00, 0x00];

        let mut output_descriptors: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        output_descriptors.push(&mut new_state, 32);

        let mut input_descriptors: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();

        input_descriptors.push(&header, 19);

        if let Some(state) = &instance.state {
            input_descriptors.push(state, 99);
        }

        input_descriptors.push(data, 35);

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        instance.state = Some(new_state);
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        debug_assert!(
            last_chunk.is_empty(),
            "Self::SEND_PADDING=true requires user not to send any last chunk"
        );

        target.copy_from_slice(&instance.state.unwrap());
    }
}
