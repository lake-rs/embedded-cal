#![no_main]
#![no_std]

use defmt_rtt as _;
use panic_probe as _;

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
#[derive(PartialEq, Eq, Debug, Clone)]
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

pub struct HashState {
    algorithm: HashAlgorithm,
    buf: [u8; 256],
    len: usize,
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
pub struct SxDesc {
    pub addr: *mut u8,
    pub next: *mut SxDesc,
    pub sz: u32,
    pub dmatag: u32,
}

#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
const LAST_DESC_PTR: *mut SxDesc = 1 as *mut SxDesc;

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

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = HashAlgorithm;
    type HashState = HashState;
    type HashResult = HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        Self::HashState {
            algorithm,
            buf: [0; 256],
            len: 0,
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        if instance.len + data.len() > 256 {
            panic!("input bigger than expected")
        }
        instance.buf[instance.len..instance.len + data.len()].copy_from_slice(data);
        instance.len += data.len();
        ()
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        let dma = self.p.global_cracencore_s.cryptmstrdma();

        let mut out = [0u8; 32];
        let out_ptr = out.as_mut_ptr();

        let mut header = [instance.algorithm as u8, 0x06, 0x00, 0x00];

        // Descriptor (output)
        let mut out_desc = SxDesc {
            addr: out_ptr,
            next: LAST_DESC_PTR,
            sz: sz(32),
            dmatag: 32,
        };

        // Descriptor (data)
        let mut data_desc = SxDesc {
            addr: instance.buf.as_ptr() as *mut u8,
            next: LAST_DESC_PTR,
            sz: sz(instance.len),
            dmatag: dmatag_for(instance.len),
        };

        // Descriptor (hash config)
        let mut header_desc = SxDesc {
            addr: header.as_mut_ptr(),
            next: &mut data_desc,
            sz: sz(4),
            dmatag: 19,
        };

        // Configure DMA source (header desc)
        dma.fetchaddrlsb()
            .write(|w| unsafe { w.bits((&mut header_desc) as *mut _ as u32) });

        // Configure DMA sink (out desc)
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

        // Wait
        while dma.status().read().fetchbusy().bit_is_set() {}
        while dma.status().read().pushbusy().bit_is_set() {}

        HashResult::Sha256(out)
    }
}
