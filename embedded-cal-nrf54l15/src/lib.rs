#![no_std]
mod aead;
mod descriptor;
mod try_rng;

use descriptor::{DescriptorChain, Input, Output};
use nrf_pac::{cracen, cracencore};

const MAX_DESCRIPTOR_CHAIN_LEN: usize = 4;

pub struct Nrf54l15Cal {
    // FIXME: No need to enable and take ownership of everything
    // it's possible to have a more granular ownership
    cracen: cracen::Cracen,
    cracen_core: cracencore::Cracencore,
}

impl embedded_cal::Cal for Nrf54l15Cal {}

impl Nrf54l15Cal {
    pub fn new(cracen: cracen::Cracen, cracen_core: cracencore::Cracencore) -> Self {
        // Enable cryptomaster
        cracen.enable().write(|w| {
            w.set_cryptomaster(true);
            w.set_rng(true);
            w.set_pkeikg(true)
        });

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

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type HashState = embedded_cal::empty::NoAlgorithms;
    type HashResult = embedded_cal::empty::NoAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::HashState, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {}
    }
}

impl embedded_cal::HmacProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type Key = embedded_cal::empty::NoAlgorithms;
    type HmacState = embedded_cal::empty::NoAlgorithms;
    type HmacResult = embedded_cal::empty::NoAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::HmacState {
        key
    }

    fn update(&mut self, state: &mut Self::HmacState, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        match state {}
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

                // Wait
                while dma.status().read().fetchbusy() {}
                while dma.status().read().pushbusy() {}
            });
        });
    }
}
