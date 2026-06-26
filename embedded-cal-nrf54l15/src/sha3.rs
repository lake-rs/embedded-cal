// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use crate::descriptor::{DescriptorChain, Input, Output};

// BA418 (SHA-3) engine mode codes.
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Variant {
    Sha3_224 = 0x06,
    Sha3_256 = 0x07,
    Sha3_384 = 0x0B,
    Sha3_512 = 0x0F,
}

impl Variant {
    const fn output_len(self) -> usize {
        match self {
            Variant::Sha3_224 => 28,
            Variant::Sha3_256 => 32,
            Variant::Sha3_384 => 48,
            Variant::Sha3_512 => 64,
        }
    }

    // Keccak absorption rate in bytes: (1600 - 2 * digest_bits) / 8.
    const fn rate(self) -> usize {
        match self {
            Variant::Sha3_224 => 144,
            Variant::Sha3_256 => 136,
            Variant::Sha3_384 => 104,
            Variant::Sha3_512 => 72,
        }
    }
}

// Largest Keccak rate across all SHA-3 variants (SHA3-224 = 144 bytes).
const MAX_RATE: usize = 144;
// Full Keccak-f[1600] permutation state (1600 bits).
const KECCAK_STATE_SIZE: usize = 200;

// BA418 DMA tags.
// DMATAG_BA418 = 5, DMATAG_CONFIG = 16.
// DMATAG_LAST (bit 5 = 32) is ORed in automatically by DescriptorChain on the
// final descriptor of each chain, so data descriptors start at 5.
const DMATAG_BA418_CONFIG: u32 = 5 | 16; // = 21
const DMATAG_BA418_DATA: u32 = 5;
// DMATAG_BA418 | DMATAG_DATATYPE(1) | DMATAG_LAST: re-injects a saved Keccak sponge
// state. DMATAG_LAST here is a BA418 semantic flag (not the chain terminator): it
// marks this descriptor as a state-load operation.
const DMATAG_BA418_INITIAL_STATE: u32 = 5 | (1 << 6) | (1 << 5); // = 101

// SHA3_SAVE_CONTEXT (bit 6 of the BA418 config word): when set, the hardware outputs
// the 200-byte intermediate Keccak sponge state instead of the final digest.
const SHA3_SAVE_CONTEXT: u8 = 1 << 6;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HashAlgorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    fn variant(&self) -> Variant {
        match self {
            HashAlgorithm::Sha3_224 => Variant::Sha3_224,
            HashAlgorithm::Sha3_256 => Variant::Sha3_256,
            HashAlgorithm::Sha3_384 => Variant::Sha3_384,
            HashAlgorithm::Sha3_512 => Variant::Sha3_512,
        }
    }
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        self.variant().output_len()
    }

    fn from_ni_id(id: u8) -> Option<Self> {
        match id {
            9 => Some(HashAlgorithm::Sha3_224),
            10 => Some(HashAlgorithm::Sha3_256),
            11 => Some(HashAlgorithm::Sha3_384),
            12 => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha3-224" => Some(HashAlgorithm::Sha3_224),
            "sha3-256" => Some(HashAlgorithm::Sha3_256),
            "sha3-384" => Some(HashAlgorithm::Sha3_384),
            "sha3-512" => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct HashState {
    variant: Variant,
    // Saved Keccak sponge state after the last absorbed full-rate block; None until
    // the first full block has been processed.
    state: Option<[u8; KECCAK_STATE_SIZE]>,
    // Partial block buffer; always contains bytes [0, buf_len).
    // Bytes [buf_len, MAX_RATE) are kept zeroed.
    buf: [u8; MAX_RATE],
    buf_len: usize,
}

// Sized for the largest possible digest (SHA3-512 = 64 bytes).
pub struct HashOutput {
    variant: Variant,
    buf: [u8; 64],
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.variant.output_len()]
    }
}

impl super::Nrf54l15Cal {
    // Sends instance.partial[..rate] to the BA418 with SHA3_SAVE_CONTEXT set,
    // saves the resulting 200-byte Keccak state, and resets the partial buffer.
    // Caller must ensure instance.buf_len == rate.
    fn sha3_absorb_block(&mut self, instance: &mut HashState) {
        let rate = instance.variant.rate();
        let header: [u8; 4] = [instance.variant as u8 | SHA3_SAVE_CONTEXT, 0x00, 0x00, 0x00];
        let mut new_state = [0u8; KECCAK_STATE_SIZE];

        let mut output_descriptors: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        output_descriptors.push(&mut new_state, 32);

        let mut input_descriptors: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        input_descriptors.push(&header, DMATAG_BA418_CONFIG);

        if let Some(state) = &instance.state {
            input_descriptors.push(state, DMATAG_BA418_INITIAL_STATE);
        }

        input_descriptors.push(&instance.buf[..rate], DMATAG_BA418_DATA);

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        instance.state = Some(new_state);
        instance.buf = [0u8; MAX_RATE];
        instance.buf_len = 0;
    }
}

impl embedded_cal::HashProvider for super::Nrf54l15Cal {
    type Algorithm = HashAlgorithm;
    type State = HashState;
    type Output = HashOutput;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        HashState {
            variant: algorithm.variant(),
            state: None,
            buf: [0u8; MAX_RATE],
            buf_len: 0,
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        let rate = instance.variant.rate();
        let mut remaining = data;

        while !remaining.is_empty() {
            let space = rate - instance.buf_len;
            let to_copy = remaining.len().min(space);
            instance.buf[instance.buf_len..instance.buf_len + to_copy]
                .copy_from_slice(&remaining[..to_copy]);
            instance.buf_len += to_copy;
            remaining = &remaining[to_copy..];

            if instance.buf_len == rate {
                self.sha3_absorb_block(instance);
            }
        }
    }

    fn finalize(&mut self, mut instance: Self::State) -> Self::Output {
        let rate = instance.variant.rate();

        // FIPS 202 multi-rate padding: place 0x06 after the last message byte, then
        // OR 0x80 into the last byte of the rate block. When buf_len == rate - 1
        // both writes land on the same byte, producing 0x86.
        instance.buf[instance.buf_len] = 0x06;
        instance.buf[rate - 1] |= 0x80;

        let out_len = instance.variant.output_len();
        let mut out_buf = [0u8; 64];

        // Config word without SHA3_SAVE_CONTEXT: final operation outputs the digest.
        let header: [u8; 4] = [instance.variant as u8, 0x00, 0x00, 0x00];

        let mut output_descriptors: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        output_descriptors.push(&mut out_buf[..out_len], 32);

        let mut input_descriptors: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        input_descriptors.push(&header, DMATAG_BA418_CONFIG);

        if let Some(state) = &instance.state {
            input_descriptors.push(state, DMATAG_BA418_INITIAL_STATE);
        }

        input_descriptors.push(&instance.buf[..rate], DMATAG_BA418_DATA);

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        HashOutput {
            variant: instance.variant,
            buf: out_buf,
        }
    }
}
