// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::p256::{
    P256_GX_BYTES, P256_GY_BYTES, P256_ORDER, bytes_to_words, ge, p256_recover_y,
};
use nrf_pac::common::{RW, Reg};
use nrf_pac::cracencore::vals::{Selcurve, Swapbytes};
use rand_core::Rng as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

// PKE data as described in nRF54L15_nRF54L10_nRF54L05_Datasheet_v1.0.pdf
const CRACEN_PKE_RAM_BASE: u32 = 0x5180_8000;
// PKE data ram space ends on microcode
const CRACEN_PKE_RAM_END: u32 = crate::microcode::BASE;
// Slot size equals HWCONFIG.MAXOPSIZE (= 0x200 on nRF54L15); see sdk-nrf pk_baremetal.c.
const SLOT_SIZE: u32 = 0x200;
// PKECOMMAND.OPBYTESM1 encodes operand width as (bytes − 1); P-256 uses 32-byte scalars → 31.
const BYTES_M1: u16 = 31;

// In big-endian (ECC) mode the BA414ep right-aligns operands within the slot:
// a 32-byte P-256 value is placed at byte offset (512 - 32) = 480 within its slot.
// See sx_pk_list_ecc_inslots() in sdk-nrf pkhardware_ba414e.c: `cryptoram += slot_size - op_size`.
const P256_SLOT_OFFSET: u32 = SLOT_SIZE - 32;

// Slot indices for ECC point multiplication (PK_OP_ECC_PTMUL = 0x22, sdk-nrf regs_commands.h).
// Derived from sdk-nrf op_slots.h: OP_SLOT_ECC_PTMUL_K/P/R and the BA414ep pointer registers.
const PKE_OPCODE_ECC_MULT: u8 = 0x22;
// OP_SLOT_ECC_PTMUL_K = 8: private scalar written here before the operation.
const SLOT_SCALAR: u32 = 8;
// OP_SLOT_ECC_PTMUL_P = 12: x-coordinate of the input point.
// y-coordinate follows in the adjacent slot (BA414ep always stores affine points as consecutive x/y slots).
const SLOT_POINT_X: u32 = 12;
const SLOT_POINT_Y: u32 = 13;
// OP_SLOT_ECC_PTMUL_R = 10: x-coordinate of the result point.
// y-coordinate follows in the adjacent slot.
const SLOT_RESULT_X: u32 = 10;
const SLOT_RESULT_Y: u32 = 11;

// Slot indices for Montgomery curve point multiplication (PK_OP_MG_PTMUL = 0x28, sdk-nrf regs_commands.h).
// Little-endian; operands sit at the START of the slot (no P256_SLOT_OFFSET equivalent).
// Montgomery uses the default BA414ep pointer registers (OP_SLOT_PTR_A/B/C from sdk-nrf op_slots.h).
// For X448, slots 0 and 1 must also be loaded with the curve prime and coefficient A before the operation
// (X25519 skips this because Selcurve::CURVE25519 has those parameters hardcoded in hardware).
const PKE_OPCODE_MONTGOMERY_PTMUL: u8 = 0x28;
// OP_SLOT_PTR_A = 6: u-coordinate of the input point (RFC 7748 notation for the Montgomery x-coordinate).
const MG_SLOT_U: u32 = 6;
// OP_SLOT_PTR_B = 8: scalar k (private key); zeroed from PKE RAM after the operation.
const MG_SLOT_K: u32 = 8;
// OP_SLOT_PTR_C = 10: output u-coordinate of the resulting point.
const MG_SLOT_OUT: u32 = 10;
// OPBYTESM1 for X448: 56-byte scalars → 55.
const X448_BYTES_M1: u16 = 55;

// Big-endian slot address (P-256): data at end of slot.
#[inline(always)]
fn slot_addr(slot: u32) -> u32 {
    CRACEN_PKE_RAM_BASE + slot * SLOT_SIZE + P256_SLOT_OFFSET
}

// Little-endian slot address (Montgomery curves): data at start of slot.
#[inline(always)]
fn montgomery_slot_addr(slot: u32) -> u32 {
    CRACEN_PKE_RAM_BASE + slot * SLOT_SIZE
}

/// # Safety
/// `addr` must be a word-aligned address within PKE RAM
/// (`CRACEN_PKE_RAM_BASE..CRACEN_PKE_RAM_END`).
unsafe fn pke_ram_word(addr: u32) -> Reg<u32, RW> {
    debug_assert!(
        addr >= CRACEN_PKE_RAM_BASE && addr + 4 <= CRACEN_PKE_RAM_END,
        "addr {addr:#010x} out of PKE RAM range {CRACEN_PKE_RAM_BASE:#010x}..{CRACEN_PKE_RAM_END:#010x}"
    );
    debug_assert!(
        addr.is_multiple_of(4),
        "addr {addr:#010x} is not word-aligned"
    );
    unsafe { Reg::from_ptr(addr as *mut u32) }
}

/// # Safety
/// `addr` must be a word-aligned address within PKE RAM
/// (`CRACEN_PKE_RAM_BASE..CRACEN_PKE_RAM_END`).
unsafe fn write_pke_le(addr: u32, data: &[u8]) {
    debug_assert!(addr.is_multiple_of(4), "function expects word sized data");
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        unsafe { pke_ram_word(addr + i as u32 * 4).write_value(v) };
    }
}

/// # Safety
/// `addr` must be a word-aligned address within PKE RAM
/// (`CRACEN_PKE_RAM_BASE..CRACEN_PKE_RAM_END`).
unsafe fn read_pke_le(addr: u32, out: &mut [u8]) {
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&unsafe { pke_ram_word(addr + i as u32 * 4).read() }.to_le_bytes());
    }
}

// X448 curve parameters (little-endian, from CRACEN SDK silexpk/target/hw/ba414/ec_curves.c).
// p = 2^448 - 2^224 - 1 (byte 28 = 0xFE; all others 0xFF in LE)
const X448_PRIME_P: [u8; 56] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
// A = 156326 (Montgomery coefficient a24)
const X448_COEFF_A: [u8; 56] = [
    0xA6, 0x62, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn clamp_x25519(k: &mut [u8; 32]) {
    k[0] &= 0xF8;
    k[31] = (k[31] | 0x40) & 0x7F;
}

fn clamp_x448(k: &mut [u8; 56]) {
    k[0] &= 0xFC;
    k[55] |= 0x80;
}

#[derive(PartialEq, Eq, Debug, Clone, Zeroize)]
pub enum DhAlgorithm {
    EcdhP256,
    X25519,
    X448,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::EcdhP256 | DhAlgorithm::X25519 => 32,
            DhAlgorithm::X448 => 56,
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        match curve.into() {
            1 => Some(DhAlgorithm::EcdhP256),
            4 => Some(DhAlgorithm::X25519),
            5 => Some(DhAlgorithm::X448),
            _ => None,
        }
    }
}

/// It is an invariant of this type that algorithm specific preconditions are upheld, concretely:
///
/// * RFC7748 curve keys (x25519, x448) are pre-clamped as in that document's decodeScalar
///   functions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SecretKey {
    EcdhP256(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::P256>),
    X25519(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::X25519>),
    X448(crate::dh_plumbing::NrfScalar<embedded_cal::plumbing::ec::X448>),
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

/// It is an invariant of this type that algorithm specific preconditions are upheld, concretely:
///
/// * RFC7748 curve keys have their unused bits cleared where applicable  (x25519; doesn't apply to
///   x448 because its length is divisible by 8).
// This is a *bit* wasteful because y is large enough even to hold a y coordinate of an OKP key;
// right now my gut feeling is that the simplifications from keeping this type simple outweigh
// that -- but maybe not, and we should switch to having an NrfScalar in there. (Shouldn't matter
// too much for the layout, and accessing x will still be the same).
//
// (We could deviate from the pattern here, as what matters is usually accessing .x, but then we'd
// also have to change the point type because the multiply_scalar_point API expects a point)
pub enum PublicKey {
    EcdhP256(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::P256>),
    X25519(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::X25519>),
    X448(crate::dh_plumbing::NrfPoint<embedded_cal::plumbing::ec::X448>),
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; crate::dh_plumbing::MAX_SCALAR],
    len: usize,
}

impl SharedSecret {
    fn from_x_coordinate<C: crate::dh_plumbing::NrfCurve>(
        point: crate::dh_plumbing::NrfPoint<C>,
    ) -> Self {
        SharedSecret {
            bytes: point.x.data,
            len: C::SCALAR_SIZE,
        }
    }
}

impl super::Nrf54l15Cal {
    fn wait_pk_ready(&mut self) {
        while self.cracen_core.pk().status().read().pkbusy() {}
        while self.cracen_core.ikg().status().read().ctrdrbgbusy() {}
    }

    // P-256 short-Weierstrass scalar multiplication on the CRACEN BA414ep PKE engine.
    // `scalar`, `px`, `py` are big-endian byte arrays; returns the resulting affine point (rx, ry)
    // also in big-endian. Zeroes the scalar slot in PKE RAM before returning.
    pub(super) fn cracen_p256_mult(
        &mut self,
        scalar: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        self.wait_pk_ready();

        self.cracen_core.pk().command().write(|w| {
            w.set_opeaddr(PKE_OPCODE_ECC_MULT);
            w.set_opbytesm1(BYTES_M1);
            w.set_selcurve(Selcurve::P256);
            w.set_swapbytes(Swapbytes::SWAPPED);
        });

        self.wait_pk_ready();

        // Safety: slot addresses are derived from slot constants, statically in PKE RAM range;
        unsafe {
            write_pke_le(slot_addr(SLOT_SCALAR), scalar);
            write_pke_le(slot_addr(SLOT_POINT_X), px);
            write_pke_le(slot_addr(SLOT_POINT_Y), py);
        }

        self.cracen_core.pk().pointers().write(|w| {
            w.set_opptra(SLOT_POINT_X as u8);
            w.set_opptrb(SLOT_SCALAR as u8);
            w.set_opptrc(SLOT_RESULT_X as u8);
        });

        self.cracen_core.pk().control().write(|w| {
            w.set_start(true);
            w.set_clearirq(true);
        });

        self.wait_pk_ready();

        let status = self.cracen_core.pk().status().read();
        debug_assert!(
            status.errorflags() == 0 && status.failptr() == 0,
            "CRACEN PKE scalar multiplication failed (errorflags={:#x}, failptr={:#x})",
            status.errorflags(),
            status.failptr(),
        );

        let mut rx = [0u8; 32];
        let mut ry = [0u8; 32];
        // Safety: slot addresses are derived from slot constants, statically in PKE RAM range;
        unsafe {
            read_pke_le(slot_addr(SLOT_RESULT_X), &mut rx);
            read_pke_le(slot_addr(SLOT_RESULT_Y), &mut ry);
            // Zero the private scalar from PKE RAM before returning.
            for i in 0..8u32 {
                pke_ram_word(slot_addr(SLOT_SCALAR) + i * 4).write_value(0u32);
            }
        }
        (rx, ry)
    }

    // Montgomery-curve scalar multiplication on CRACEN hardware.
    // `curve_params` carries (prime, coeff_a) for curves that need them written to slots 0/1
    // (X448); pass `None` for hardware-accelerated curves (X25519) that don't.
    // Both operands must be pre-clamped per RFC 7748 before calling.
    fn cracen_montgomery_mult<const N: usize>(
        &mut self,
        scalar: &[u8; N],
        u_coord: &[u8; N],
        bytes_m1: u16,
        selcurve: Selcurve,
        edwards: bool,
        curve_params: Option<(&[u8], &[u8])>,
    ) -> [u8; N] {
        self.wait_pk_ready();

        self.cracen_core.pk().command().write(|w| {
            w.set_opeaddr(PKE_OPCODE_MONTGOMERY_PTMUL);
            w.set_opbytesm1(bytes_m1);
            w.set_selcurve(selcurve);
            w.set_edwards(edwards);
            w.set_swapbytes(Swapbytes::NATIVE);
        });

        self.wait_pk_ready();

        // Safety: slot addresses are derived from slot constants, statically in PKE RAM range;
        unsafe {
            if let Some((prime, coeff_a)) = curve_params {
                write_pke_le(montgomery_slot_addr(0), prime);
                write_pke_le(montgomery_slot_addr(1), coeff_a);
            }
            write_pke_le(montgomery_slot_addr(MG_SLOT_U), u_coord);
            write_pke_le(montgomery_slot_addr(MG_SLOT_K), scalar);
        }

        self.cracen_core.pk().pointers().write(|w| {
            w.set_opptra(MG_SLOT_U as u8);
            w.set_opptrb(MG_SLOT_K as u8);
            w.set_opptrc(MG_SLOT_OUT as u8);
        });

        self.cracen_core.pk().control().write(|w| {
            w.set_start(true);
            w.set_clearirq(true);
        });

        self.wait_pk_ready();

        let status = self.cracen_core.pk().status().read();
        debug_assert!(
            status.errorflags() == 0 && status.failptr() == 0,
            "CRACEN Montgomery multiplication failed (errorflags={:#x}, failptr={:#x})",
            status.errorflags(),
            status.failptr(),
        );

        let mut result = [0u8; N];
        // Safety: slot addresses are derived from slot constants, statically in PKE RAM range;
        unsafe {
            read_pke_le(montgomery_slot_addr(MG_SLOT_OUT), &mut result);
            // Zero the private scalar from PKE RAM before returning.
            for i in 0..(N / 4) {
                pke_ram_word(montgomery_slot_addr(MG_SLOT_K) + i as u32 * 4).write_value(0u32);
            }
        }
        result
    }

    pub(super) fn cracen_x25519_mult(&mut self, scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
        self.cracen_montgomery_mult(scalar, u_coord, BYTES_M1, Selcurve::CURVE25519, false, None)
    }

    // Curve params are written to slots 0/1; both operands must be pre-clamped.
    pub(super) fn cracen_x448_mult(&mut self, scalar: &[u8; 56], u_coord: &[u8; 56]) -> [u8; 56] {
        self.cracen_montgomery_mult(
            scalar,
            u_coord,
            X448_BYTES_M1,
            Selcurve::NOACCEL,
            true,
            Some((&X448_PRIME_P, &X448_COEFF_A)),
        )
    }
}

impl embedded_cal::DhProvider for super::Nrf54l15Cal {
    type Algorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            DhAlgorithm::EcdhP256 => loop {
                let mut scalar = [0u8; 32];
                // Error = Infallible
                self.fill_bytes(&mut scalar);
                let w = bytes_to_words(&scalar);
                if w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                    return VisibleSecretKey(SecretKey::EcdhP256(scalar.into()));
                }
            },
            DhAlgorithm::X25519 => {
                let mut scalar = [0u8; 32];
                self.fill_bytes(&mut scalar);
                clamp_x25519(&mut scalar);
                VisibleSecretKey(SecretKey::X25519(scalar.into()))
            }
            DhAlgorithm::X448 => {
                let mut scalar = [0u8; 56];
                self.fill_bytes(&mut scalar);
                clamp_x448(&mut scalar);
                VisibleSecretKey(SecretKey::X448(scalar.into()))
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        match &secretkey.0 {
            SecretKey::EcdhP256(scalar) => scalar.as_ref().as_slice(),
            SecretKey::X25519(scalar) => scalar.as_ref().as_slice(),
            SecretKey::X448(scalar) => scalar.as_ref().as_slice(),
        }
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let secret = match alg {
            DhAlgorithm::EcdhP256 => SecretKey::EcdhP256(
                <[u8; _]>::try_from(secret)
                    .map_err(|_| embedded_cal::ImportError)?
                    .into(),
            ),
            DhAlgorithm::X25519 => {
                let mut scalar =
                    <[u8; _]>::try_from(secret).map_err(|_| embedded_cal::ImportError)?;
                // RFC7748 says "Implementations MUST accept non-canonical values" about public
                // keys, and has no concrete words around loading secret keys (which is not really
                // a necessary operation anyway); following the same notational logic (data is
                // clipped silently), we also do not err here.
                clamp_x25519(&mut scalar);
                SecretKey::X25519(scalar.into())
            }
            DhAlgorithm::X448 => {
                let mut scalar =
                    <[u8; _]>::try_from(secret).map_err(|_| embedded_cal::ImportError)?;
                clamp_x448(&mut scalar);
                SecretKey::X448(scalar.into())
            }
        };
        Ok(VisibleSecretKey(secret))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        match public {
            PublicKey::EcdhP256(point) => point.x.as_ref().as_slice(),
            PublicKey::X25519(point) => point.x.as_ref().as_slice(),
            PublicKey::X448(point) => point.x.as_ref().as_slice(),
        }
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        use crate::dh_plumbing::NrfPoint;

        match alg {
            DhAlgorithm::EcdhP256 => {
                let x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                let y = p256_recover_y(&x)?;
                Ok(PublicKey::EcdhP256(NrfPoint {
                    x: x.into(),
                    y: y.into(),
                }))
            }
            DhAlgorithm::X25519 => {
                let mut x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                x[31] &= 0x7F;
                Ok(PublicKey::X25519(NrfPoint {
                    x: x.into(),
                    y: [0; _].into(),
                }))
            }
            DhAlgorithm::X448 => {
                let x: [u8; _] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
                Ok(PublicKey::X448(NrfPoint {
                    x: x.into(),
                    y: [0; _].into(),
                }))
            }
        }
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        use embedded_cal::plumbing::ec::{Ec, EcPrimitives};

        match (private, public) {
            (SecretKey::EcdhP256(private), PublicKey::EcdhP256(public)) => {
                let result = self.p256().multiply_scalar_point(private, public);
                Ok(SharedSecret::from_x_coordinate(result))
            }
            (SecretKey::X25519(k), PublicKey::X25519(public)) => {
                // Not clamping of k: Was done at generation / loading time.
                // No clearing of the 256 bit of the public key: Was done at loading time.
                let result = self.x25519().multiply_scalar_point(k, public);
                Ok(SharedSecret::from_x_coordinate(result))
            }
            (SecretKey::X448(k), PublicKey::X448(public)) => {
                // Not clamping of k: Was done at generation / loading time.
                let result = self.x448().multiply_scalar_point(k, public);
                Ok(SharedSecret::from_x_coordinate(result))
            }
            _ => Err(embedded_cal::IncompatibleKeys),
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        use crate::dh_plumbing::{NrfPoint, NrfScalar};
        use embedded_cal::plumbing::ec::*;

        match private {
            SecretKey::EcdhP256(scalar) => {
                const P256_G: NrfPoint<P256> = NrfPoint {
                    x: NrfScalar::<P256>::from_const(P256_GX_BYTES),
                    y: NrfScalar::<P256>::from_const(P256_GY_BYTES),
                };
                PublicKey::EcdhP256(self.p256().multiply_scalar_point(scalar, &P256_G))
            }
            SecretKey::X25519(k) => {
                let mut base_u = [0u8; 32];
                base_u[0] = 9; // X25519 base point u-coordinate = 9 (little-endian)
                let base = NrfPoint {
                    x: base_u.into(),
                    y: [0; _].into(),
                };
                let public = self.x25519().multiply_scalar_point(k, &base);
                // FIXME: Verify that the output key needs no bit-clearing (because it is on the
                // curve by construction)
                PublicKey::X25519(public)
            }
            SecretKey::X448(k) => {
                let mut base_u = [0u8; 56];
                base_u[0] = 5; // X448 base point u-coordinate = 5 (little-endian)
                let base = NrfPoint {
                    x: base_u.into(),
                    y: [0; _].into(),
                };
                PublicKey::X448(self.x448().multiply_scalar_point(k, &base))
            }
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secret.bytes[..secret.len]
    }
}
