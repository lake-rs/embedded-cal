// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Implementation of embedded-cal for the Arm TrustZone CryptoCell-312 in the nRF5340 application
//! core.
//!
//! All engines are driven through their registers (as exposed by [`nrf_pac`]); no precompiled
//! runtime library is involved. The register-level sequences follow the nRF5340 Product
//! Specification (CRYPTOCELL chapter) and, where that is silent, the open source (BSD-3-Clause)
//! CryptoCell-312 runtime shipped with Trusted Firmware-M
//! (`lib/ext/cryptocell-312-runtime`), which is used as documentation only.
//!
//! What the hardware provides, and what this crate builds from it:
//!
//! * HASH engine: SHA-224/SHA-256 compression ([`embedded_cal::plumbing::hash::Sha2Short`]).
//! * AES engine: AES-CCM (in two passes: CBC-MAC, then CTR).
//! * PKA engine: a modular big-number ALU, with no elliptic curve operations of its own. P-256,
//!   X25519 and X448 scalar multiplication and ECDSA are built from modular arithmetic on it in
//!   the `ec` module.
//! * TRNG: raw entropy (health-tested in hardware), conditioned with SHA-256.
#![no_std]

mod aead;
mod dh;
mod dh_plumbing;
mod ec;
mod pka;
mod try_rng;

use core::sync::atomic::{Ordering, fence};
use embedded_cal::empty::EmptyCal;
use nrf_pac::{
    cc_aes, cc_ctl, cc_din, cc_dout, cc_hash, cc_host_rgf, cc_misc, cc_pka, cc_rng, cryptocell,
};
use zeroize::Zeroize;

/// Largest single DIN/DOUT DMA transfer (the size fields take at most 2^16 - 1 bytes), rounded
/// down to a multiple of both the AES block (16 B) and the SHA-256 block (64 B).
const MAX_DMA_CHUNK: usize = 0xFFC0;

/// The CryptoCell register blocks used by [`Nrf5340Cal`].
///
/// All `CC_*` blocks share the base address 0x5084_5000; the PAC splits them by engine.
pub struct Peripherals {
    pub cryptocell: cryptocell::Cryptocell,
    pub cc_aes: cc_aes::CcAes,
    pub cc_ctl: cc_ctl::CcCtl,
    pub cc_din: cc_din::CcDin,
    pub cc_dout: cc_dout::CcDout,
    pub cc_hash: cc_hash::CcHash,
    pub cc_host_rgf: cc_host_rgf::CcHostRgf,
    pub cc_misc: cc_misc::CcMisc,
    pub cc_pka: cc_pka::CcPka,
    pub cc_rng: cc_rng::CcRng,
}

impl Peripherals {
    /// The secure mapping of all CryptoCell register blocks.
    ///
    /// FIXME: Like for the nRF54L15, nothing enforces that only one instance of these exists.
    pub const fn secure() -> Self {
        Self {
            cryptocell: nrf_pac::CRYPTOCELL_S,
            cc_aes: nrf_pac::CC_AES_S,
            cc_ctl: nrf_pac::CC_CTL_S,
            cc_din: nrf_pac::CC_DIN_S,
            cc_dout: nrf_pac::CC_DOUT_S,
            cc_hash: nrf_pac::CC_HASH_S,
            cc_host_rgf: nrf_pac::CC_HOST_RGF_S,
            cc_misc: nrf_pac::CC_MISC_S,
            cc_pka: nrf_pac::CC_PKA_S,
            cc_rng: nrf_pac::CC_RNG_S,
        }
    }
}

pub struct Nrf5340Cal {
    // FIXME: No need to enable and take ownership of everything
    // it's possible to have a more granular ownership
    cryptocell: cryptocell::Cryptocell,
    cc_aes: cc_aes::CcAes,
    cc_ctl: cc_ctl::CcCtl,
    cc_din: cc_din::CcDin,
    cc_dout: cc_dout::CcDout,
    cc_hash: cc_hash::CcHash,
    cc_host_rgf: cc_host_rgf::CcHostRgf,
    cc_misc: cc_misc::CcMisc,
    cc_pka: cc_pka::CcPka,
    cc_rng: cc_rng::CcRng,

    /// TRNG ring oscillator currently in use (index into `try_rng::SAMPLE_COUNTS`).
    trng_rosc: usize,

    // Null-provider for everything we do *not* implement
    empty: EmptyCal,
}

impl embedded_cal::Cal for Nrf5340Cal {
    type DhProvider = Self;
    type AeadProvider = Self;
    type HashProvider = EmptyCal;
    type HmacProvider = EmptyCal;
    type SignProvider = EmptyCal;

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

    fn sign(&mut self) -> &mut Self::SignProvider {
        &mut self.empty
    }
}

impl Nrf5340Cal {
    pub fn new(p: Peripherals) -> Self {
        // Power up the subsystem; per the PS, engine registers are only accessible while the
        // respective engine clock is enabled.
        p.cryptocell.enable().write(|w| w.set_enable(true));

        p.cc_misc.dma_clk().write(|w| w.set_enable(true));
        p.cc_misc.aes_clk().write(|w| w.set_enable(true));
        p.cc_misc.hash_clk().write(|w| w.set_enable(true));
        p.cc_misc.pka_clk().write(|w| w.set_enable(true));
        p.cc_rng.rng_clk().write(|w| w.set_enable(true));
        while {
            let s = p.cc_misc.clk_status().read();
            !(s.dma_clk() && s.aes_clk() && s.hash_clk() && s.pka_clk())
        } {}

        // All completion signalling is polled from IRR, which shows raw (unmasked) status. Mask
        // every source so nothing is ever forwarded to the NVIC.
        p.cc_host_rgf
            .imr()
            .write_value(cc_host_rgf::regs::Imr(0xFFFF_FFFF));
        p.cc_host_rgf
            .icr()
            .write_value(cc_host_rgf::regs::Icr(0xFFFF_FFFF));

        let mut cal = Self {
            cryptocell: p.cryptocell,
            cc_aes: p.cc_aes,
            cc_ctl: p.cc_ctl,
            cc_din: p.cc_din,
            cc_dout: p.cc_dout,
            cc_hash: p.cc_hash,
            cc_host_rgf: p.cc_host_rgf,
            cc_misc: p.cc_misc,
            cc_pka: p.cc_pka,
            cc_rng: p.cc_rng,
            trng_rosc: 0,
            empty: EmptyCal,
        };

        cal.trng_configure();

        cal
    }

    /// Waits until the symmetric engines (AES, HASH and their DMA) are idle.
    fn wait_crypto_idle(&self) {
        while self.cc_ctl.crypto_busy().read().status() == cc_ctl::vals::CryptoBusyStatus::Busy {}
    }

    /// Runs a memory-to-memory DMA transfer through whichever engine `CRYPTO_CTL` selects.
    ///
    /// When `dst` is null, no output DMA is configured (HASH and CBC-MAC only produce state in
    /// registers).
    ///
    /// # Safety
    ///
    /// * `src` must be valid for reads of `len` bytes, and `dst` (if not null) for writes of
    ///   `len` bytes, for the duration of the call. They may be identical (in-place operation),
    ///   but must not otherwise overlap.
    /// * Both must be in memory the CryptoCell DMA can reach (SRAM or flash).
    /// * `len` must be in `1..=0xFFFF`.
    ///
    /// The function only returns after the engine signalled completion, so the memory is no
    /// longer accessed by hardware afterwards.
    unsafe fn dma_raw(&mut self, src: *const u8, dst: *mut u8, len: usize) {
        debug_assert!((1..=0xFFFF).contains(&len));

        self.cc_host_rgf.icr().write(|w| w.set_sym_dma_clear(true));

        // Make sure all CPU writes to the buffers are visible before the DMA starts.
        fence(Ordering::SeqCst);

        if !dst.is_null() {
            self.cc_dout.dst_mem_addr().write_value(dst as u32);
            self.cc_dout
                .dst_mem_size()
                .write(|w| w.set_size(len as u32));
        }
        // Writing the source size starts the transfer.
        self.cc_din.src_mem_addr().write_value(src as u32);
        self.cc_din.src_mem_size().write(|w| w.set_size(len as u32));

        loop {
            let irr = self.cc_host_rgf.irr().read();
            if irr.ahb_err_int() {
                panic!("CryptoCell DMA bus error");
            }
            if irr.sym_dma_int() {
                break;
            }
            core::hint::spin_loop();
        }
        self.cc_host_rgf.icr().write(|w| w.set_sym_dma_clear(true));

        // Make sure the CPU does not read the output before the DMA has written it.
        fence(Ordering::SeqCst);
    }

    /// Feeds `data` (1..=[`MAX_DMA_CHUNK`] bytes) into the selected engine, without output DMA.
    fn dma_in(&mut self, data: &[u8]) {
        assert!((1..=MAX_DMA_CHUNK).contains(&data.len()));
        // Safety: data is a live shared slice of valid length; dma_raw blocks until the hardware
        // is done with it.
        unsafe { self.dma_raw(data.as_ptr(), core::ptr::null_mut(), data.len()) };
    }

    /// Feeds `data` (1..=[`MAX_DMA_CHUNK`] bytes) through the selected engine and writes the
    /// output back in place.
    fn dma_in_place(&mut self, data: &mut [u8]) {
        assert!((1..=MAX_DMA_CHUNK).contains(&data.len()));
        // Safety: data is a live exclusive slice of valid length; source and destination are
        // identical, which is the permitted in-place case.
        unsafe { self.dma_raw(data.as_ptr(), data.as_mut_ptr(), data.len()) };
    }
}

impl Drop for Nrf5340Cal {
    fn drop(&mut self) {
        self.trng_stop();

        // Power-down sequence from the nRF5340 PS: no pending tasks, idle, interrupts cleared,
        // power-down request, then disable.
        while self.cc_host_rgf.host_cc_is_idle().read().host_cc_is_idle()
            != cc_host_rgf::vals::HostCcIsIdle::Idle
        {}
        self.cc_rng
            .rng_icr()
            .write_value(cc_rng::regs::RngIcr(0xFFFF_FFFF));
        self.cc_host_rgf
            .icr()
            .write_value(cc_host_rgf::regs::Icr(0xFFFF_FFFF));

        self.cc_misc.dma_clk().write(|w| w.set_enable(false));
        self.cc_misc.aes_clk().write(|w| w.set_enable(false));
        self.cc_misc.hash_clk().write(|w| w.set_enable(false));
        self.cc_misc.pka_clk().write(|w| w.set_enable(false));
        self.cc_rng.rng_clk().write(|w| w.set_enable(false));

        self.cc_host_rgf
            .host_powerdown()
            .write(|w| w.set_host_powerdown(true));
        self.cryptocell.enable().write(|w| w.set_enable(false));
    }
}

// SHA-2 initial hash values (FIPS 180-4 5.3.2 and 5.3.3); HASH_H[0] holds H0.
const SHA224_IV: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[derive(Clone)]
pub struct HashState {
    /// Intermediate hash value H0..H7.
    h: [u32; 8],
    /// Number of bytes compressed so far (mirrored into HASH_CUR_LEN).
    processed: u64,
    /// Digest length of the selected variant.
    out_len: usize,
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

impl embedded_cal::plumbing::Plumbing for Nrf5340Cal {}

impl embedded_cal::plumbing::hash::Hash for Nrf5340Cal {}

impl embedded_cal::plumbing::hash::Sha2Short for Nrf5340Cal {
    const SUPPORTED: bool = true;
    // The engine can pad (AUTO_HW_PADDING), but software padding keeps the state a plain
    // intermediate hash value that can be cloned and resumed at any block boundary.
    const SEND_PADDING: bool = true;
    const FIRST_CHUNK_SIZE: usize = 64;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        let (h, out_len) = match variant {
            embedded_cal::plumbing::hash::Sha2ShortVariant::Sha256 => (SHA256_IV, 32),
            // SHA-224 runs the same compression function from a different starting point.
            embedded_cal::plumbing::hash::Sha2ShortVariant::Sha244 => (SHA224_IV, 28),
        };

        Self::State {
            h,
            processed: 0,
            out_len,
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(64),
            "Chunking requirements laid out in Self::FIRST_CHUNK_SIZE not upheld."
        );

        if data.is_empty() {
            return;
        }
        self.sha2_compress(&mut instance.h, instance.processed, data);
        instance.processed += data.len() as u64;
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        debug_assert!(
            last_chunk.is_empty(),
            "Self::SEND_PADDING=true requires user not to send any last chunk"
        );

        let mut digest = [0u8; 32];
        for (out, h) in digest.as_chunks_mut::<4>().0.iter_mut().zip(instance.h) {
            *out = h.to_be_bytes();
        }
        target[..instance.out_len].copy_from_slice(&digest[..instance.out_len]);
    }
}

impl Nrf5340Cal {
    /// Runs the SHA-256 compression function over whole 64-byte blocks of `data`, starting from
    /// (and updating) the intermediate hash value `h`.
    ///
    /// Sequence after `ProcessHashDrv()` of the CC312 runtime, minus hardware padding.
    fn sha2_compress(&mut self, h: &mut [u32; 8], mut processed: u64, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(64));

        // Each transfer starts from a freshly loaded state, so nothing needs to persist inside
        // the engine between transfers.
        for chunk in data.chunks(MAX_DMA_CHUNK) {
            self.sha2_compress_chunk(h, processed, chunk);
            processed += chunk.len() as u64;
        }
    }

    fn sha2_compress_chunk(&mut self, h: &mut [u32; 8], processed: u64, data: &[u8]) {
        self.wait_crypto_idle();
        self.cc_host_rgf
            .icr()
            .write_value(cc_host_rgf::regs::Icr(0xFFFF_FFFF));

        self.cc_ctl
            .crypto_ctl()
            .write(|w| w.set_mode(cc_ctl::vals::Mode::HashActive));
        self.cc_hash.hash_pad().write(|w| w.set_enable(true));
        self.cc_hash
            .hash_select()
            .write(|w| w.set_engine(cc_hash::vals::Engine::Hash));
        self.cc_hash.hash_cur_len_0().write_value(processed as u32);
        self.cc_hash
            .hash_cur_len_1()
            .write_value((processed >> 32) as u32);
        self.cc_hash
            .hash_control()
            .write(|w| w.set_mode(cc_hash::vals::Mode::Sha256));
        // The runtime loads H7 first and H0 last.
        for i in (0..8).rev() {
            self.cc_hash.hash_h(i).write_value(h[i]);
        }

        self.dma_in(data);

        while self.cc_ctl.hash_busy().read().status() == cc_ctl::vals::HashBusyStatus::Busy {}
        for i in (0..8).rev() {
            h[i] = self.cc_hash.hash_h(i).read();
        }
    }

    /// One-shot SHA-256 over the concatenation of `parts`, with software padding.
    ///
    /// Used internally for ECDSA and for conditioning TRNG output.
    pub(crate) fn sha256(&mut self, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = SHA256_IV;
        let mut processed: u64 = 0;
        let mut total: u64 = 0;
        let mut buf = [0u8; 64];
        let mut fill = 0;

        for part in parts {
            let mut part = *part;
            total += part.len() as u64;

            if fill > 0 {
                let take = (64 - fill).min(part.len());
                buf[fill..fill + take].copy_from_slice(&part[..take]);
                fill += take;
                part = &part[take..];
                if fill == 64 {
                    self.sha2_compress(&mut h, processed, &buf);
                    processed += 64;
                    fill = 0;
                }
            }

            // Whole blocks go to the DMA straight from the caller's memory.
            let whole = part.len() & !63;
            if whole > 0 {
                self.sha2_compress(&mut h, processed, &part[..whole]);
                processed += whole as u64;
                part = &part[whole..];
            }

            if !part.is_empty() {
                // Only reachable with an empty buffer: a partially filled one was either topped
                // up to a full block or has absorbed all of `part` above.
                buf[..part.len()].copy_from_slice(part);
                fill = part.len();
            }
        }

        // FIPS 180-4 5.1.1 padding
        buf[fill] = 0x80;
        buf[fill + 1..].fill(0);
        if fill + 1 > 56 {
            self.sha2_compress(&mut h, processed, &buf);
            processed += 64;
            buf.fill(0);
        }
        buf[56..].copy_from_slice(&(total * 8).to_be_bytes());
        self.sha2_compress(&mut h, processed, &buf);
        buf.zeroize();

        let mut digest = [0u8; 32];
        for (out, h) in digest.as_chunks_mut::<4>().0.iter_mut().zip(h) {
            *out = h.to_be_bytes();
        }
        digest
    }
}
