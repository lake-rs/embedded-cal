// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! # CryptoCell-312 TRNG
//!
//! The TRNG collects 192 bits at a time into the entropy holding registers (EHR), after a von
//! Neumann corrector and the hardware's continuous (CRNGT) and autocorrelation health tests.
//!
//! The sequence follows `LLF_RND_StartTrngHW()` and `LLF_RND_TRNG_ReadEhrData()` of the CC312
//! runtime in its default "full entropy" mode, including its default sample counts per ring
//! oscillator: when a collection fails (health test error or watchdog timeout), the next, slower
//! ring oscillator is tried.
//!
//! Like the runtime, which collects two EHRs (384 bits) per 256 bits of security strength, every
//! 32 bytes of output are derived from two EHRs; here, conditioned with SHA-256 (a vetted
//! conditioning function per NIST SP 800-90B 3.1.5.1.1) instead of the runtime's DRBG.

use crate::CryptoCellCal;
use nrf_pac::cc_rng::{regs, vals::TrngConfigRoscLen};
use zeroize::Zeroize;

/// SAMPLE_CNT (CPU clock cycles between noise samples) for ROSC1..ROSC3; the runtime's
/// `CC_CONFIG_SAMPLE_CNT_ROSC_*` defaults. (ROSC4 has a sample count of 0, i.e. is not used.)
pub(crate) const SAMPLE_COUNTS: [u32; 3] = [5000, 1000, 500];
const ROSC_LENGTHS: [TrngConfigRoscLen; 3] = [
    TrngConfigRoscLen::Rosc1,
    TrngConfigRoscLen::Rosc2,
    TrngConfigRoscLen::Rosc3,
];

/// Failed collections tolerated per output block before the hardware is considered broken (two
/// full rounds through all oscillators).
const MAX_TRNG_FAILURES: usize = 2 * SAMPLE_COUNTS.len();

const EHR_WORDS: usize = 6;

/// RNG_IMR value of the runtime's full entropy mode (`LLF_RNG_INT_MASK_ON_FETRNG_MODE`): EHR_VALID,
/// AUTOCORR_ERR and WATCHDOG unmasked.
const RNG_IMR_FE_MODE: u32 = 0xFFFF_FFEC;

impl CryptoCellCal {
    /// (Re)starts the TRNG with the currently selected ring oscillator.
    pub(crate) fn trng_configure(&mut self) {
        let sample_count = SAMPLE_COUNTS[self.trng_rosc];
        let rng = self.cc_rng;

        rng.rng_clk().write(|w| w.set_enable(true));
        rng.rng_sw_reset().write(|w| w.set_reset(true));
        // The reset is complete once the sample count can be written again.
        loop {
            rng.rng_clk().write(|w| w.set_enable(true));
            rng.sample_cnt().write_value(sample_count);
            if rng.sample_cnt().read() == sample_count {
                break;
            }
        }

        rng.noise_source().write(|w| w.set_enable(false));
        rng.rng_icr().write_value(regs::RngIcr(0xFFFF_FFFF));
        rng.rng_imr().write_value(regs::RngImr(RNG_IMR_FE_MODE));
        rng.trng_config()
            .write(|w| w.set_rosc_len(ROSC_LENGTHS[self.trng_rosc]));
        // No bypasses of the von Neumann corrector or the health tests.
        rng.trng_debug().write_value(regs::TrngDebug(0));
    }

    pub(crate) fn trng_stop(&mut self) {
        self.cc_rng.noise_source().write(|w| w.set_enable(false));
        self.cc_rng.rng_icr().write_value(regs::RngIcr(0xFFFF_FFFF));
    }

    /// Collects one EHR (192 bits); `None` if a health test or the watchdog fired.
    fn trng_collect_ehr(&mut self) -> Option<[u32; EHR_WORDS]> {
        let rng = self.cc_rng;

        // Upper bound on CPU cycles for one collection, after LLF_RND_CalcMaxTrngTime(): 192 bits
        // at SAMPLE_CNT cycles each, times 4 for the von Neumann corrector, times 2 for margin.
        let max_cycles = 192 * 4 * SAMPLE_COUNTS[self.trng_rosc] * 2;
        rng.rng_watchdog_val().write_value(max_cycles);
        rng.noise_source().write(|w| w.set_enable(true));

        loop {
            let irr = self.cc_host_rgf.irr().read();
            if irr.ahb_err_int() {
                panic!("CryptoCell bus error");
            }
            if irr.rng_int() {
                break;
            }
            core::hint::spin_loop();
        }

        rng.noise_source().write(|w| w.set_enable(false));
        let isr = rng.rng_isr().read();
        rng.rng_icr().write_value(regs::RngIcr(0xFFFF_FFFF));
        // HOST_IRR must be cleared after RNG_ISR.
        self.cc_host_rgf.icr().write(|w| w.set_rng_clear(true));

        let ok = isr.ehr_valid_int()
            && !isr.autocorr_err_int()
            && !isr.crngt_err_int()
            && !isr.vnc_err_int()
            && !isr.watchdog_int();
        if !ok {
            return None;
        }

        let mut ehr = [0u32; EHR_WORDS];
        for (i, word) in ehr.iter_mut().enumerate() {
            *word = rng.ehr_data(i).read();
        }
        Some(ehr)
    }

    /// Produces 32 bytes from 384 bits of conditioned TRNG output.
    fn trng_block(&mut self) -> [u8; 32] {
        let mut failures = 0;
        loop {
            if let Some(mut a) = self.trng_collect_ehr() {
                if let Some(mut b) = self.trng_collect_ehr() {
                    let mut raw = [0u8; 2 * EHR_WORDS * 4];
                    for (out, w) in raw
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(a.iter().chain(&b))
                    {
                        *out = w.to_le_bytes();
                    }
                    let block = self.sha256(&[&raw]);
                    raw.zeroize();
                    a.zeroize();
                    b.zeroize();
                    return block;
                }
                a.zeroize();
            }

            // Health tests failing indicates that the noise source may be untrustworthy; after a
            // bounded number of retries with other oscillators, assume faulty or tampered-with
            // hardware rather than looping forever or handing out bad randomness.
            failures += 1;
            if failures > MAX_TRNG_FAILURES {
                panic!("RNG hardware failure");
            }
            self.trng_rosc = (self.trng_rosc + 1) % SAMPLE_COUNTS.len();
            self.trng_configure();
        }
    }
}

impl rand_core::TryCryptoRng for CryptoCellCal {}
impl rand_core::TryRng for CryptoCellCal {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(32) {
            let mut block = self.trng_block();
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        Ok(())
    }
}
