#![no_std]
mod descriptor;

use descriptor::{Descriptor, DescriptorChain, LAST_DESC_PTR};

const BLOCK_SIZE: usize = 128;
// Compile-time check: BLOCK_SIZE must be a power of two
// and the size must be greater or eq than one hash block
const _: () = {
    assert!(BLOCK_SIZE >= 128);
    assert!(BLOCK_SIZE.is_power_of_two());
};
pub struct Nrf54l15Cal {
    p: nrf54l15_app_pac::Peripherals,
}

impl Nrf54l15Cal {
    pub fn new(p: nrf54l15_app_pac::Peripherals) -> Self {
        // Enable cryptomaster
        p.global_cracen_s.enable().write(|w| {
            w.cryptomaster().set_bit();
            w.rng().set_bit();
            w.pkeikg().set_bit()
        });

        Self { p }
    }
}

impl Drop for Nrf54l15Cal {
    fn drop(&mut self) {
        // Disable cryptomaster on drop
        self.p.global_cracen_s.enable().write(|w| {
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
        if data.len() <= (BLOCK_SIZE - instance.block_bytes_used) {
            instance.block[instance.block_bytes_used..instance.block_bytes_used + data.len()]
                .copy_from_slice(data);
            instance.block_bytes_used += data.len();

            return;
        }

        // Case 2: data does NOT fit
        let total = instance.block_bytes_used + data.len();
        let next_full_boundary = total & !(BLOCK_SIZE - 1); // round down to nearest multiple of BLOCK_SIZE
        let bytes_from_data = next_full_boundary.saturating_sub(instance.block_bytes_used);

        let dma = self.p.global_cracencore_s.cryptmstrdma();

        let mut new_state: [u8; 64] = [0x00; 64];

        let header: [u8; 4] = [instance.algorithm as u8, 0x00, 0x00, 0x00];

        let state_len = instance.algorithm.internal_state_len();

        let mut out_desc = Descriptor {
            addr: new_state.as_mut_ptr(),
            next: LAST_DESC_PTR,
            sz: sz(state_len),
            dmatag: 32,
        };

        let mut descriptors = DescriptorChain::new();

        descriptors.push(Descriptor {
            addr: header.as_ptr() as *mut u8,
            next: core::ptr::null_mut(),
            sz: sz(4),
            dmatag: 19,
        });

        if let Some(state) = &instance.state {
            descriptors.push(Descriptor {
                addr: state.as_ptr() as *mut u8,
                next: core::ptr::null_mut(),
                sz: sz(state_len),
                dmatag: 99,
            });
        }

        if instance.block_bytes_used > 0 {
            descriptors.push(Descriptor {
                addr: instance.block.as_ptr() as *mut u8,
                next: core::ptr::null_mut(),
                sz: instance.block_bytes_used as u32,
                dmatag: 3,
            });
        }

        descriptors.push(Descriptor {
            addr: data.as_ptr() as *mut u8,
            next: core::ptr::null_mut(),
            sz: 0x2000_0000 | bytes_from_data as u32,
            dmatag: 35,
        });

        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits(descriptors.first() as u32) });

        dma.pushaddrlsb()
            .write(|w| unsafe { w.bits((&mut out_desc) as *mut _ as u32) });

        dma.config().write(|w| {
            w.fetchctrlindirect().set_bit();
            w.pushctrlindirect().set_bit();
            w.fetchstop().clear_bit();
            w.pushstop().clear_bit();
            w.softrst().clear_bit()
        });

        dma.start().write(|w| {
            w.startfetch().set_bit();
            w.startpush().set_bit()
        });

        while dma.status().read().fetchbusy().bit_is_set() {}
        while dma.status().read().pushbusy().bit_is_set() {}

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
        let dma = self.p.global_cracencore_s.cryptmstrdma();

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

        let mut out_desc = Descriptor {
            addr: out.as_mut_ptr(),
            next: LAST_DESC_PTR,
            sz: sz(algo_len),
            dmatag: 32,
        };

        let header: [u8; 4] = [instance.algorithm as u8, 0x04, 0x00, 0x00];

        let mut descriptors = DescriptorChain::new();

        descriptors.push(Descriptor {
            addr: header.as_ptr() as *mut u8,
            next: core::ptr::null_mut(),
            sz: sz(4),
            dmatag: 19,
        });

        if let Some(state) = &instance.state {
            descriptors.push(Descriptor {
                addr: state.as_ptr() as *mut u8,
                next: core::ptr::null_mut(),
                sz: sz(state_len),
                dmatag: 99,
            });
        }

        descriptors.push(Descriptor {
            addr: instance.block.as_ptr() as *mut u8,
            next: core::ptr::null_mut(),
            sz: instance.block_bytes_used as u32,
            dmatag: 3,
        });

        descriptors.push(Descriptor {
            addr: pad.as_ptr() as *mut u8,
            next: core::ptr::null_mut(),
            sz: 0x2000_0000 | padding_size as u32,
            dmatag: 35,
        });

        // Configure DMA source
        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits(descriptors.first() as u32) });

        // Configure DMA sink
        dma.pushaddrlsb()
            .write(|w| unsafe { w.bits((&mut out_desc) as *mut _ as u32) });

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
