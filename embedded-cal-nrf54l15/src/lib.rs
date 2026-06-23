// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]

mod aead;
mod descriptor;
mod dh;
mod microcode;
mod try_rng;

use descriptor::{DescriptorChain, Input, Output};
use embedded_cal::empty::EmptyCal;
use nrf_pac::{cracen, cracencore};

// CCM encrypt needs 4 input descriptors (config, key, header+aad, plaintext) and
// 2 output descriptors (ciphertext, tag). Decrypt needs 5 input (+ expected tag).
const MAX_DESCRIPTOR_CHAIN_LEN: usize = 6;

pub struct Nrf54l15Cal {
    // FIXME: No need to enable and take ownership of everything
    // it's possible to have a more granular ownership
    cracen: cracen::Cracen,
    cracen_core: cracencore::Cracencore,

    // Null-provider for everything we do *not* implement
    empty: EmptyCal<false>,
}

impl embedded_cal::Cal for Nrf54l15Cal {
    type DhProvider = Self;
    type AeadProvider = Self;
    type HashProvider = EmptyCal<false>;
    type HmacProvider = EmptyCal<false>;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        &mut self.empty
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        &mut self.empty
    }
}

impl Nrf54l15Cal {
    pub fn new(cracen: cracen::Cracen, cracen_core: cracencore::Cracencore) -> Self {
        // Enable cryptomaster
        cracen.enable().write(|w| {
            w.set_cryptomaster(true);
            w.set_rng(true);
            w.set_pkeikg(true)
        });

        // Load PKE microcode immediately after enabling the PKE/IKG block
        unsafe { microcode::load() };

        // Enable the NDRNG; it stays on until Drop.
        cracen_core
            .rngcontrol()
            .control()
            .modify(|w| w.set_enable(true));

        // Discard the first FIFO word produced after the startup conditioning period
        while cracen_core.rngcontrol().fifolevel().read() == 0 {}
        let _ = cracen_core.rngcontrol().fifo(0).read();

        Self {
            cracen,
            cracen_core,
            empty: EmptyCal,
        }
    }
}

impl Drop for Nrf54l15Cal {
    fn drop(&mut self) {
        // Disable NDRNG
        self.cracen_core
            .rngcontrol()
            .control()
            .modify(|w| w.set_enable(false));

        // Disable cryptomaster on drop
        self.cracen.enable().write(|w| {
            w.set_cryptomaster(false);
            w.set_rng(false);
            w.set_pkeikg(false)
        });
    }
}

#[derive(Clone)]
pub struct HashState {
    // We could instead make this unconditional and then set state (in init) to 0x6a, 0x09, 0xe6,
    // 0x67, ... (the big-endian version of the SHA256 starting points 0x6a09e667u32), but the
    // hardware has the values, so why not use them.
    state: Option<[u8; 32]>,
}

pub enum HashResult {
    Sha256([u8; 32]),
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
        }
    }
}

impl embedded_cal::plumbing::Plumbing for Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Hash for Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Sha2Short for Nrf54l15Cal {
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

        let mut output_descriptors: DescriptorChain<Output, MAX_DESCRIPTOR_CHAIN_LEN> =
            DescriptorChain::new();
        output_descriptors.push(&mut new_state, 32);

        let mut input_descriptors: DescriptorChain<Input, MAX_DESCRIPTOR_CHAIN_LEN> =
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

impl Nrf54l15Cal {
    fn execute_cryptomaster_dma<const N: usize>(
        &mut self,
        input_descriptors: &mut DescriptorChain<Input, N>,
        output_descriptors: &mut DescriptorChain<Output, N>,
    ) {
        input_descriptors.with_first_pointer(|input_ptr| {
            output_descriptors.with_first_pointer(|output_ptr| {
                let dma = self.cracen_core.cryptmstrdma();
                // Configure DMA source
                dma.fetchaddrlsb().write_value(input_ptr);

                // Configure DMA sink
                dma.pushaddrlsb().write_value(output_ptr);

                dma.config().write(|w| {
                    w.set_fetchctrlindirect(true);
                    w.set_pushctrlindirect(true);
                    w.set_fetchstop(false);
                    w.set_pushstop(false);
                    w.set_softrst(false)
                });

                // Start DMA
                dma.start().write(|w| {
                    w.set_startfetch(true);
                    w.set_startpush(true)
                });

                // Wait for all three busy bits to clear, matching REG_STATUS_BUSY_MASK
                // from the Nordic SDK: FETCHER_BUSY (0x01) | PUSHER_BUSY (0x02) |
                // PUSHER_WAITING_FIFO (0x20). Without PUSHER_WAITING_FIFO the output
                // buffers may not be fully written when we return.
                while {
                    let s = dma.status().read();
                    s.fetchbusy() || s.pushbusy() || s.pushwaitingfifo()
                } {}
            });
        });
    }
}
