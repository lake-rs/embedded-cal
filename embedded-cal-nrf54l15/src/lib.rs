#![no_main]
#![no_std]

use defmt_rtt as _;
use panic_probe as _;

const BLOCK_SIZE: usize = 64;

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
#[derive(PartialEq, Eq, Debug, Clone, Copy, defmt::Format)]
pub enum HashAlgorithm {
    Sha256 = 0x08,
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }

    // FIXME: See from_cose_number definition
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            -10 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

#[derive(defmt::Format)]
pub struct HashState {
    algorithm: HashAlgorithm,
    state: Option<[u8; 32]>,
    block: [u8; BLOCK_SIZE],
    block_bytes_used: usize,
    processed_bytes: usize,
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

#[repr(C)]
#[derive(Debug, Clone, Copy, defmt::Format)]
pub struct Descriptor {
    pub addr: *mut u8,
    pub next: *mut Descriptor,
    pub sz: u32,
    pub dmatag: u32,
}

impl Descriptor {
    pub fn empty() -> Self {
        Self {
            addr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            sz: 0,
            dmatag: 0,
        }
    }
}

#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;

fn dmatag_for(input: usize) -> u32 {
    const TAG_BASE: u32 = 0x23;
    const TAG_0: u32 = 0x000;
    const TAG_1: u32 = 0x300;
    const TAG_2: u32 = 0x200;
    const TAG_3: u32 = 0x100;

    if input == 0 {
        return TAG_BASE | 0x400;
    }

    match input % 4 {
        0 => TAG_BASE | TAG_0, // -> 0x023 = 35
        1 => TAG_BASE | TAG_1, // -> 0x323 = 803
        2 => TAG_BASE | TAG_2, // -> 0x223 = 547
        3 => TAG_BASE | TAG_3, // -> 0x123 = 291
        _ => panic!("impossible state"),
    }
}

fn sz(n: usize) -> u32 {
    const DMA_REALIGN: usize = 0x2000_0000;
    let group_end = (n.saturating_sub(1) / 4 + 1) * 4;
    (group_end | DMA_REALIGN) as u32
}

fn sha256_padding(msg_len: usize, out: &mut [u8; 128]) -> usize {
    out[0] = 0x80;

    // compute zero padding length
    let mod_len = (msg_len + 1) % 64;

    let zero_pad_len = if mod_len <= 56 {
        // fits in one block
        56 - mod_len
    } else {
        // needs two blocks
        64 + 56 - mod_len
    };

    for i in 1..=zero_pad_len {
        out[i] = 0;
    }

    // append 64-bit length (big endian)
    let bit_len = (msg_len as u64) * 8;
    let be = bit_len.to_be_bytes();

    let length_pos = 1 + zero_pad_len;
    for i in 0..8 {
        out[length_pos + i] = be[i];
    }

    1 + zero_pad_len + 8
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
        if data.len() <= (BLOCK_SIZE - instance.block_bytes_used) as usize {
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

        let mut new_state: [u8; 32] = [0x00; 32];

        let header: [u8; 4] = [instance.algorithm as u8, 0x00, 0x00, 0x00];

        let mut out_desc = Descriptor {
            addr: new_state.as_mut_ptr(),
            next: LAST_DESC_PTR,
            sz: sz(32),
            dmatag: 32,
        };

        let mut pad_desc = Descriptor {
            addr: data.as_ptr() as *mut u8,
            next: LAST_DESC_PTR,
            sz: 0x2000_0000 | bytes_from_data as u32, // 63
            dmatag: 35,
        };

        let mut data_desc = Descriptor {
            addr: instance.block.as_ptr() as *mut u8,
            next: &mut pad_desc,
            sz: instance.block_bytes_used as u32,
            dmatag: 3,
        };

        let mut in_desc = Descriptor {
            addr: header.as_ptr() as *mut u8,
            next: &mut data_desc,
            sz: sz(4),
            dmatag: 19,
        };

        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits((&mut in_desc) as *mut _ as u32) });

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
        ()
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        let dma = self.p.global_cracencore_s.cryptmstrdma();

        let mut pad: [u8; 128] = [0x00; 128];
        let padding_size = sha256_padding(
            instance.processed_bytes + instance.block_bytes_used,
            &mut pad,
        );

        let mut out: [u8; 32] = [0x00; 32];

        let mut out_desc = Descriptor {
            addr: out.as_mut_ptr(),
            next: LAST_DESC_PTR,
            sz: sz(32),
            dmatag: 32,
        };

        let header: [u8; 4] = match instance.state {
            Some(_) => [instance.algorithm as u8, 0x04, 0x00, 0x00],
            None => [instance.algorithm as u8, 0x06, 0x00, 0x00],
        };

        let mut in_desc = Descriptor::empty();
        let mut state_desc = Descriptor::empty();
        let mut data_desc = Descriptor::empty();
        let mut padding_desc = Descriptor::empty();

        match instance.state {
            None => {
                // Direct hash, the input is formatted as
                // in -> data
                in_desc.addr = header.as_ptr() as *mut u8;
                in_desc.next = &mut data_desc;
                in_desc.sz = sz(4);
                in_desc.dmatag = 19;

                data_desc.addr = instance.block.as_ptr() as *mut u8;
                data_desc.next = LAST_DESC_PTR;
                data_desc.sz = sz(instance.block_bytes_used);
                data_desc.dmatag = dmatag_for(instance.block_bytes_used);
            }
            Some(state) => {
                // Incremental hash, the input is formatted as
                // in -> state -> data -> padding
                in_desc.addr = header.as_ptr() as *mut u8;
                in_desc.next = &mut state_desc;
                in_desc.sz = sz(4);
                in_desc.dmatag = 19;

                state_desc.addr = state.as_ptr() as *mut u8;
                state_desc.next = &mut data_desc;
                state_desc.sz = sz(32);
                state_desc.dmatag = 99;

                data_desc.addr = instance.block.as_ptr() as *mut u8;
                data_desc.next = &mut padding_desc;
                data_desc.sz = instance.block_bytes_used as u32;
                data_desc.dmatag = 3;

                padding_desc.addr = pad.as_ptr() as *mut u8;
                padding_desc.next = LAST_DESC_PTR;
                padding_desc.sz = 0x2000_0000 | padding_size as u32;
                padding_desc.dmatag = 35;
            }
        }

        // Configure DMA source
        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits((&mut in_desc) as *mut _ as u32) });

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

        HashResult::Sha256(out)
    }
}
