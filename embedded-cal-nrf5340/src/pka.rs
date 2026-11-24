// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! # CryptoCell-312 PKA engine
//!
//! The PKA is a big-number ALU working on 32 *virtual registers* in its 6 KiB SRAM. The
//! `MEMORY_MAP[i]` registers map virtual register `i` to an SRAM address (in 32-bit words);
//! `PKA_L[j]` hold operand sizes in bits, selected per operation by the opcode's `LEN` field.
//! Register 0 holds the modulus N, register 1 its Barrett tag NP; registers 30 and 31 (T0, T1) are
//! scratch space of the hardware.
//!
//! The mapping changes as operations run (see [`Pka::reg_addr`]), so CPU accesses always resolve
//! the current address of a register through `MEMORY_MAP` first.
//!
//! Data in the SRAM is little-endian: the least significant 32-bit word comes first.
//!
//! Source for the sequences: `pka.c`, `pka.h` and `pka_hw_defs.h` of the CC312 runtime
//! (`PkaInitPka()`, `PkaSetRegsMapTab()`, `PkaSetRegsSizesTab()`, `PKA_EXEC_OPERATION`,
//! `PKA_HW_LOAD_BLOCK_TO_PKA_MEM`, `PKA_HW_READ_BLOCK_FROM_PKA_MEM`).

use crate::Nrf5340Cal;
use core::marker::PhantomData;
use nrf_pac::cc_pka::{CcPka, vals};

/// Virtual register holding the modulus.
pub(crate) const REG_N: u8 = 0;
/// Virtual register holding the modulus' Barrett tag.
pub(crate) const REG_NP: u8 = 1;
const REG_T0: u8 = 30;
const REG_T1: u8 = 31;
const REG_COUNT: u32 = 32;

/// Size table entry with the exact modulus size; used for all modular operations
/// (`LEN_ID_N_BITS`).
const LEN_N: u8 = 0;
/// Size table entry with the modulus size plus one PKA word; used for plain copies
/// (`LEN_ID_N_PKA_REG_BITS`).
const LEN_REG: u8 = 1;

const PKA_WORD_BITS: u32 = 64;
const PKA_SRAM_WORDS: u32 = 6 * 1024 / 4;

/// An operand of a PKA operation.
#[derive(Clone, Copy)]
pub(crate) enum Operand {
    /// Virtual register index (0..=31).
    Reg(u8),
    /// 5-bit immediate.
    Imm(u8),
}

/// The PKA engine, set up for one modulus size.
///
/// This borrows the CAL exclusively. When dropped, all register memory is wiped so that no
/// secret (scalars, nonces, intermediate points) outlives the operation in PKA SRAM.
pub(crate) struct Pka<'a> {
    regs: CcPka,
    /// Size of each virtual register in 32-bit words.
    reg_words: u32,
    _cal: PhantomData<&'a mut Nrf5340Cal>,
}

impl Nrf5340Cal {
    /// Initializes the PKA for operations modulo a number of `modulus_bits` bits.
    ///
    /// The modulus itself is set through [`Pka::set_modulus`].
    pub(crate) fn pka(&mut self, modulus_bits: u32) -> Pka<'_> {
        Pka::new(self.cc_pka, modulus_bits)
    }
}

impl Pka<'_> {
    fn new(regs: CcPka, modulus_bits: u32) -> Self {
        // Register size as computed by PkaInitPka() for moduli of at least 144 bits: the modulus
        // rounded up to 32-bit words, plus one extra PKA word, in whole PKA words.
        debug_assert!(modulus_bits >= 2 * (PKA_WORD_BITS + 8));
        let reg_pka_words = (modulus_bits.div_ceil(32) * 32).div_ceil(PKA_WORD_BITS) + 1;
        let reg_words = reg_pka_words * (PKA_WORD_BITS / 32);
        debug_assert!(REG_COUNT * reg_words <= PKA_SRAM_WORDS);

        let pka = Self {
            regs,
            reg_words,
            _cal: PhantomData,
        };

        pka.wait_done();

        // PkaSetRegsMapTab(): consecutive registers, T0 and T1 last.
        for i in 0..REG_COUNT {
            let addr = i * reg_words;
            debug_assert!(addr.is_multiple_of(2));
            // The ADDR field starts at bit 1 and counts 64-bit units, so the raw register value
            // equals the address in 32-bit words, which is what the runtime writes.
            pka.regs
                .memory_map(i as usize)
                .write(|w| w.set_addr((addr / 2) as u16));
        }
        pka.regs.n_np_t0_t1_addr().write(|w| {
            w.set_n_virtual_addr(REG_N);
            w.set_np_virtual_addr(REG_NP);
            w.set_t0_virtual_addr(REG_T0);
            w.set_t1_virtual_addr(REG_T1);
        });

        // PkaSetRegsSizesTab()
        let full_op_bits = PKA_WORD_BITS * (modulus_bits.div_ceil(PKA_WORD_BITS) + 1);
        pka.regs
            .pka_l(LEN_N as usize)
            .write(|w| w.set_op_size(modulus_bits as u16));
        pka.regs
            .pka_l(LEN_REG as usize)
            .write(|w| w.set_op_size(full_op_bits as u16));
        for i in 2..8 {
            pka.regs
                .pka_l(i)
                .write(|w| w.set_op_size((reg_words * 32) as u16));
        }

        pka.clear_sram();

        pka
    }

    fn wait_done(&self) {
        while self.regs.pka_done().read().status() != vals::PkaDoneStatus::Completed {}
    }

    /// Current SRAM address (in 32-bit words) of a virtual register.
    ///
    /// This must be looked up for every CPU access, as the runtime's `PKA_GET_REG_ADDRESS` does:
    /// modular additions, subtractions and multiplications compute into T0 and then swap the
    /// `MEMORY_MAP` entries of the result register and T0, so a register does not stay at the
    /// address it was mapped to initially. (Observed on an nRF5340 DK with full register dumps.)
    fn reg_addr(&self, reg: u8) -> u32 {
        debug_assert!((reg as u32) < REG_COUNT);
        // The map must not be read while operations may still swap entries.
        self.wait_done();
        // The ADDR field starts at bit 1 and counts 64-bit units; see `Pka::new`.
        self.regs.memory_map(reg as usize).read().addr() as u32 * 2
    }

    /// Zeroes all virtual registers.
    fn clear_sram(&self) {
        self.wait_done();
        self.regs.pka_sram_waddr().write_value(0);
        for _ in 0..REG_COUNT * self.reg_words {
            self.regs.pka_sram_wdata().write_value(0);
        }
    }

    /// Writes a number given as little-endian 32-bit words into a register, zero-extending it to
    /// the full register size.
    pub(crate) fn load(&self, reg: u8, words: &[u32]) {
        debug_assert!(words.len() as u32 <= self.reg_words);
        self.load_iter(reg, words.iter().copied());
    }

    /// Writes a number given as big-endian bytes (whole words) into a register.
    pub(crate) fn load_be(&self, reg: u8, bytes: &[u8]) {
        debug_assert!(bytes.len().is_multiple_of(4));
        self.load_iter(
            reg,
            bytes
                .as_rchunks::<4>()
                .1
                .iter()
                .rev()
                .map(|c| u32::from_be_bytes(*c)),
        );
    }

    /// Writes a number given as little-endian bytes (whole words) into a register.
    pub(crate) fn load_le(&self, reg: u8, bytes: &[u8]) {
        debug_assert!(bytes.len().is_multiple_of(4));
        self.load_iter(
            reg,
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c)),
        );
    }

    /// Writes a small value into a register.
    pub(crate) fn set_word(&self, reg: u8, value: u32) {
        self.load(reg, &[value]);
    }

    fn load_iter(&self, reg: u8, words: impl Iterator<Item = u32>) {
        // SRAM is not accessible while the engine is working.
        self.wait_done();
        // Consecutive WDATA writes auto-increment the address.
        self.regs.pka_sram_waddr().write_value(self.reg_addr(reg));
        let mut written = 0;
        for w in words {
            self.regs.pka_sram_wdata().write_value(w);
            written += 1;
        }
        for _ in written..self.reg_words {
            self.regs.pka_sram_wdata().write_value(0);
        }
    }

    /// Reads the low `out.len()` words of a register.
    pub(crate) fn read(&self, reg: u8, out: &mut [u32]) {
        self.read_iter(reg, out.iter_mut());
    }

    /// Reads the low `out.len()` bytes (whole words) of a register as a big-endian number.
    pub(crate) fn read_be(&self, reg: u8, out: &mut [u8]) {
        debug_assert!(out.len().is_multiple_of(4));
        let mut words = [0u32; 16];
        let words = &mut words[..out.len() / 4];
        self.read(reg, words);
        for (chunk, w) in out.as_rchunks_mut::<4>().1.iter_mut().rev().zip(words) {
            *chunk = w.to_be_bytes();
        }
    }

    /// Reads the low `out.len()` bytes (whole words) of a register as a little-endian number.
    pub(crate) fn read_le(&self, reg: u8, out: &mut [u8]) {
        debug_assert!(out.len().is_multiple_of(4));
        let mut words = [0u32; 16];
        let words = &mut words[..out.len() / 4];
        self.read(reg, words);
        for (chunk, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *chunk = w.to_le_bytes();
        }
    }

    fn read_iter<'w>(&self, reg: u8, out: impl Iterator<Item = &'w mut u32>) {
        self.wait_done();
        // Consecutive RDATA reads auto-increment the address.
        self.regs.pka_sram_raddr().write_value(self.reg_addr(reg));
        for w in out {
            *w = self.regs.pka_sram_rdata().read();
        }
    }

    /// Sets the modulus (register N) and its Barrett tag (register NP).
    pub(crate) fn set_modulus(&self, modulus: &[u32], barrett_tag: &[u32]) {
        self.load(REG_N, modulus);
        self.load(REG_NP, barrett_tag);
    }

    /// Queues one operation (`PKA_EXEC_OPERATION`); `tag` carries the third operand of the
    /// multiply-accumulate operations and is 0 otherwise.
    fn exec(&self, opcode: vals::Opcode, len: u8, a: Operand, b: Operand, r: u8, tag: u8) {
        while !self.regs.pka_pipe().read().status() {}
        self.regs.opcode().write(|w| {
            w.set_opcode(opcode);
            w.set_len(len);
            match a {
                Operand::Reg(reg) => w.set_reg_a(reg),
                Operand::Imm(imm) => {
                    w.set_const_a(vals::ConstA::Constant);
                    w.set_reg_a(imm);
                }
            }
            match b {
                Operand::Reg(reg) => w.set_reg_b(reg),
                Operand::Imm(imm) => {
                    w.set_const_b(vals::ConstB::Constant);
                    w.set_reg_b(imm);
                }
            }
            w.set_reg_r(r);
            w.set_tag(tag);
        });
    }

    /// r = (a + b) mod N; inputs must be reduced.
    pub(crate) fn mod_add(&self, r: u8, a: u8, b: u8) {
        self.exec(
            vals::Opcode::ModAddInc,
            LEN_N,
            Operand::Reg(a),
            Operand::Reg(b),
            r,
            0,
        );
    }

    /// r = (a - b) mod N; inputs must be reduced.
    pub(crate) fn mod_sub(&self, r: u8, a: u8, b: u8) {
        self.exec(
            vals::Opcode::ModSubDecNeg,
            LEN_N,
            Operand::Reg(a),
            Operand::Reg(b),
            r,
            0,
        );
    }

    /// r = (a * b) mod N, fully reduced.
    pub(crate) fn mod_mul(&self, r: u8, a: u8, b: u8) {
        self.exec(
            vals::Opcode::ModMul,
            LEN_N,
            Operand::Reg(a),
            Operand::Reg(b),
            r,
            0,
        );
    }

    /// r = a^e mod N (`PKA_MOD_EXP`), with the exponent in register `e`; all three registers must
    /// be distinct.
    pub(crate) fn mod_exp(&self, r: u8, a: u8, e: u8) {
        debug_assert!(
            r != a && r != e && a != e,
            "mod_exp registers must be distinct"
        );
        self.exec(
            vals::Opcode::ModExp,
            LEN_N,
            Operand::Reg(a),
            Operand::Reg(e),
            r,
            0,
        );
    }

    /// r = a (`PKA_COPY`: OR with immediate 0).
    pub(crate) fn copy(&self, r: u8, a: u8) {
        self.exec(
            vals::Opcode::Orcopyset0,
            LEN_REG,
            Operand::Reg(a),
            Operand::Imm(0),
            r,
            0,
        );
    }
}

impl Drop for Pka<'_> {
    fn drop(&mut self) {
        self.clear_sram();
    }
}

/// Constant-time conditional swap of two register indices.
///
/// The PKA performs the same operations either way; only which registers they act on changes.
/// The swap is computed with a mask, without branching on `bit`; [`core::hint::black_box`] keeps
/// the compiler from turning it back into a branch.
#[inline(always)]
pub(crate) fn cswap(a: &mut u8, b: &mut u8, bit: u8) {
    let mask = core::hint::black_box(0u8.wrapping_sub(bit & 1));
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}
