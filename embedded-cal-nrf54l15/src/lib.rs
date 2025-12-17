#![no_std]
mod descriptor;

use descriptor::DescriptorChain;

const BLOCK_SIZE: usize = 128;
const MAX_DESCRIPTOR_CHAIN_LEN: usize = 4;
// Compile-time check: BLOCK_SIZE must be a power of two
// and the size must be greater or eq than one hash block
const _: () = {
    assert!(BLOCK_SIZE >= 128);
    assert!(BLOCK_SIZE.is_power_of_two());
};
pub struct Nrf54l15Cal {
    // TODO: No need to enable and take ownership of everything
    // it's possible to have a more granular ownership
    cracen: nrf54l15_app_pac::GlobalCracenS,
    cracen_core: nrf54l15_app_pac::GlobalCracencoreS,
}

impl Nrf54l15Cal {
    pub fn new(
        cracen: nrf54l15_app_pac::GlobalCracenS,
        cracen_core: nrf54l15_app_pac::GlobalCracencoreS,
    ) -> Self {
        // Enable cryptomaster
        cracen.enable().write(|w| {
            w.cryptomaster().set_bit();
            w.rng().set_bit();
            w.pkeikg().set_bit()
        });

        Self {
            cracen,
            cracen_core,
        }
    }
}

impl Drop for Nrf54l15Cal {
    fn drop(&mut self) {
        // Disable cryptomaster on drop
        self.cracen.enable().write(|w| {
            w.cryptomaster().clear_bit();
            w.rng().clear_bit();
            w.pkeikg().clear_bit()
        });
    }
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Choice of a supported hash algorithm.
///
/// Values taken from:
/// https://github.com/nrfconnect/sdk-nrf/blob/8dd452357395abad28a4c2310d6c8d9560016881/subsys/nrf_security/src/drivers/cracen/sxsymcrypt/src/hash.c#L31-L48
///
/// Enum values currently represent the first byte of the engine header.
pub enum HashAlgorithm {
    Sha256 = 0x08,
    Sha384 = 0x10,
    Sha512 = 0x20,
}

impl HashAlgorithm {
    fn internal_state_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 64,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    // FIXME: I am using the values from RFC 9054 here, is that correct?
    // https://www.rfc-editor.org/rfc/rfc9054.html#name-sha-2-hash-algorithms
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            -10 => Some(HashAlgorithm::Sha256),
            // -16 => Some(HashAlgorithm::Sha256),
            -43 => Some(HashAlgorithm::Sha384),
            -44 => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Some(HashAlgorithm::Sha256),
            7 => Some(HashAlgorithm::Sha384),
            8 => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            "sha-384" => Some(HashAlgorithm::Sha384),
            "sha-512" => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }
}

pub struct HashState {
    algorithm: HashAlgorithm,
    state: Option<[u8; 64]>,
    block: [u8; BLOCK_SIZE],
    block_bytes_used: usize,
    processed_bytes: usize,
}

pub enum HashResult {
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
            HashResult::Sha384(r) => &r[..],
            HashResult::Sha512(r) => &r[..],
        }
    }
}

fn sz(n: usize) -> u32 {
    const DMA_REALIGN: usize = 0x2000_0000;
    let group_end = (n.saturating_sub(1) / 4 + 1) * 4;
    (group_end | DMA_REALIGN) as u32
}

fn sha256_padding(msg_len: usize, out: &mut [u8; 256]) -> usize {
    sha2_padding(msg_len, 64, 56, 8, out)
}

fn sha512_padding(msg_len: usize, out: &mut [u8; 256]) -> usize {
    sha2_padding(msg_len, 128, 112, 16, out)
}

fn sha2_padding(
    msg_len: usize,
    block_size: usize,
    length_offset: usize,
    length_bytes: usize,
    out: &mut [u8; 256],
) -> usize {
    out[0] = 0x80;

    let rem = (msg_len + 1) % block_size;

    let zero_pad = if rem <= length_offset {
        length_offset - rem
    } else {
        length_offset + (block_size - rem)
    };

    for b in &mut out[1..=zero_pad] {
        *b = 0;
    }

    let bit_len = (msg_len as u128) * 8;
    let len_bytes_be = bit_len.to_be_bytes();

    let start = 1 + zero_pad;
    out[start..start + length_bytes].copy_from_slice(&len_bytes_be[(16 - length_bytes)..]);

    1 + zero_pad + length_bytes
}

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = HashAlgorithm;
    type HashState = HashState;
    type HashResult = HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        Self::HashState {
            algorithm,
            state: None,
            block: [0; BLOCK_SIZE],
            processed_bytes: 0,
            block_bytes_used: 0,
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        // Case 1: data fits entirely inside the current block
        if data.len() < (BLOCK_SIZE - instance.block_bytes_used) {
            instance.block[instance.block_bytes_used..instance.block_bytes_used + data.len()]
                .copy_from_slice(data);
            instance.block_bytes_used += data.len();

            return;
        }

        // Case 2: data does NOT fit
        let total = instance.block_bytes_used + data.len();
        let next_full_boundary = total & !(BLOCK_SIZE - 1); // round down to nearest multiple of BLOCK_SIZE
        let bytes_from_data = next_full_boundary.saturating_sub(instance.block_bytes_used);

        let mut new_state: [u8; 64] = [0x00; 64];

        let header: [u8; 4] = [instance.algorithm as u8, 0x00, 0x00, 0x00];

        let state_len = instance.algorithm.internal_state_len();

        let mut output_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();
        output_descriptors.push(new_state.as_mut_ptr(), sz(state_len), 32);

        let mut input_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();

        input_descriptors.push(header.as_ptr() as *mut u8, sz(4), 19);

        if let Some(state) = &instance.state {
            input_descriptors.push(state.as_ptr() as *mut u8, sz(state_len), 99);
        }

        if instance.block_bytes_used > 0 {
            input_descriptors.push(
                instance.block.as_ptr() as *mut u8,
                instance.block_bytes_used as u32,
                3,
            );
        }

        input_descriptors.push(
            data.as_ptr() as *mut u8,
            0x2000_0000 | bytes_from_data as u32,
            35,
        );

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        instance.state = Some(new_state);
        instance.processed_bytes += instance.block_bytes_used + bytes_from_data;

        // reset buffer
        instance.block = [0u8; BLOCK_SIZE];
        instance.block_bytes_used = 0;

        // copy leftover bytes into empty buffer
        let data_left = data.len() - bytes_from_data;
        instance.block[0..data_left].copy_from_slice(&data[bytes_from_data..]);
        instance.block_bytes_used += data_left;
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        let mut pad: [u8; 256] = [0x00; 256];

        let padding_size = match instance.algorithm {
            HashAlgorithm::Sha256 => sha256_padding(
                instance.processed_bytes + instance.block_bytes_used,
                &mut pad,
            ),
            HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => sha512_padding(
                instance.processed_bytes + instance.block_bytes_used,
                &mut pad,
            ),
        };

        let algo_len = embedded_cal::HashAlgorithm::len(&instance.algorithm);
        let state_len = instance.algorithm.internal_state_len();

        let mut out: [u8; 64] = [0x00; 64];

        let mut output_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();
        output_descriptors.push(out.as_mut_ptr(), sz(algo_len), 32);

        let header: [u8; 4] = [instance.algorithm as u8, 0x04, 0x00, 0x00];

        let mut input_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();

        input_descriptors.push(header.as_ptr() as *mut u8, sz(4), 19);

        if let Some(state) = &instance.state {
            input_descriptors.push(state.as_ptr() as *mut u8, sz(state_len), 99);
        }

        input_descriptors.push(
            instance.block.as_ptr() as *mut u8,
            instance.block_bytes_used as u32,
            3,
        );

        input_descriptors.push(
            pad.as_ptr() as *mut u8,
            0x2000_0000 | padding_size as u32,
            35,
        );

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        match instance.algorithm {
            HashAlgorithm::Sha256 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out[..32]);
                HashResult::Sha256(arr)
            }
            HashAlgorithm::Sha384 => {
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&out[..48]);
                HashResult::Sha384(arr)
            }
            HashAlgorithm::Sha512 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&out[..64]);
                HashResult::Sha512(arr)
            }
        }
    }
}

impl Nrf54l15Cal {
    fn execute_cryptomaster_dma<const N: usize>(
        &mut self,
        input_descriptors: &mut DescriptorChain<N>,
        output_descriptors: &mut DescriptorChain<N>,
    ) -> () {
        let dma = self.cracen_core.cryptmstrdma();
        // Configure DMA source
        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits(input_descriptors.first() as u32) });

        // Configure DMA sink
        dma.pushaddrlsb()
            .write(|w| unsafe { w.bits(output_descriptors.first() as u32) });

        dma.config().write(|w| {
            w.fetchctrlindirect().set_bit();
            w.pushctrlindirect().set_bit();
            w.fetchstop().clear_bit();
            w.pushstop().clear_bit();
            w.softrst().clear_bit()
        });

        // Start DMA
        dma.start().write(|w| {
            w.startfetch().set_bit();
            w.startpush().set_bit()
        });

        // Wait
        while dma.status().read().fetchbusy().bit_is_set() {}
        while dma.status().read().pushbusy().bit_is_set() {}
    }
}
