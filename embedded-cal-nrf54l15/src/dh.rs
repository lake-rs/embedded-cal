use embedded_cal::DhAlgorithm as _;
use embedded_cal::p256::{P256_ORDER, bytes_to_words, ge, p256_recover_y};
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

fn pke_ram_word(addr: u32) -> Reg<u32, RW> {
    debug_assert!(
        addr >= CRACEN_PKE_RAM_BASE && addr + 4 <= CRACEN_PKE_RAM_END,
        "addr {addr:#010x} out of PKE RAM range {CRACEN_PKE_RAM_BASE:#010x}..{CRACEN_PKE_RAM_END:#010x}"
    );
    debug_assert!(addr % 4 == 0, "addr {addr:#010x} is not word-aligned");
    // Safety: addr is always a valid CRACEN PKE RAM address derived from CRACEN_PKE_RAM_BASE.
    unsafe { Reg::from_ptr(addr as *mut u32) }
}

fn write_pke_le(addr: u32, data: &[u8]) {
    debug_assert!(data.len() % 4 == 0, "function expects word sized data");
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        pke_ram_word(addr + i as u32 * 4).write_value(v);
    }
}

fn read_pke_le(addr: u32, out: &mut [u8]) {
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&pke_ram_word(addr + i as u32 * 4).read().to_le_bytes());
    }
}

// P-256 generator point (big-endian bytes, for use with cracen_ecc_mult).
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    alg: DhAlgorithm,
    // First `alg.output_length()` bytes are valid.
    scalar: [u8; 56],
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

pub struct PublicKey {
    alg: DhAlgorithm,
    // First `alg.output_length()` bytes are valid.
    x: [u8; 56],
    // Used only for P-256 (recovered on import).
    y: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 56],
    len: usize,
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

        write_pke_le(slot_addr(SLOT_SCALAR), scalar);
        write_pke_le(slot_addr(SLOT_POINT_X), px);
        write_pke_le(slot_addr(SLOT_POINT_Y), py);

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
        read_pke_le(slot_addr(SLOT_RESULT_X), &mut rx);
        read_pke_le(slot_addr(SLOT_RESULT_Y), &mut ry);
        // Zero the private scalar from PKE RAM before returning.
        for i in 0..8u32 {
            pke_ram_word(slot_addr(SLOT_SCALAR) + i * 4).write_value(0u32);
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

        if let Some((prime, coeff_a)) = curve_params {
            write_pke_le(montgomery_slot_addr(0), prime);
            write_pke_le(montgomery_slot_addr(1), coeff_a);
        }

        write_pke_le(montgomery_slot_addr(MG_SLOT_U), u_coord);
        write_pke_le(montgomery_slot_addr(MG_SLOT_K), scalar);

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
        read_pke_le(montgomery_slot_addr(MG_SLOT_OUT), &mut result);
        // Zero the private scalar from PKE RAM before returning.
        for i in 0..(N / 4) {
            pke_ram_word(montgomery_slot_addr(MG_SLOT_K) + i as u32 * 4).write_value(0u32);
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
        let mut scalar = [0u8; 56];
        match alg {
            DhAlgorithm::EcdhP256 => loop {
                // Error = Infallible
                self.fill_bytes(&mut scalar[..32]);
                let scalar32: [u8; 32] = scalar[..32].try_into().expect("slice is always 32 bytes");
                let w = bytes_to_words(&scalar32);
                if w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                    return VisibleSecretKey(SecretKey { alg, scalar });
                }
            },
            DhAlgorithm::X25519 => {
                self.fill_bytes(&mut scalar[..32]);
                VisibleSecretKey(SecretKey { alg, scalar })
            }
            DhAlgorithm::X448 => {
                self.fill_bytes(&mut scalar[..56]);
                VisibleSecretKey(SecretKey { alg, scalar })
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secretkey.0.scalar[..secretkey.0.alg.output_length()]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let expected = alg.output_length();
        if secret.len() != expected {
            return Err(embedded_cal::ImportError);
        }
        let mut scalar = [0u8; 56];
        scalar[..expected].copy_from_slice(secret);
        Ok(VisibleSecretKey(SecretKey { alg, scalar }))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        &public.x[..public.alg.output_length()]
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        let expected = alg.output_length();
        if data.len() != expected {
            return Err(embedded_cal::ImportError);
        }
        let mut x = [0u8; 56];
        x[..expected].copy_from_slice(data);
        let y = match alg {
            DhAlgorithm::EcdhP256 => {
                let x32: [u8; 32] = x[..32].try_into().expect("slice is always 32 bytes");
                p256_recover_y(&x32)?
            }
            DhAlgorithm::X25519 | DhAlgorithm::X448 => [0u8; 32],
        };
        Ok(PublicKey { alg, x, y })
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        match private.alg {
            DhAlgorithm::EcdhP256 => {
                let mut scalar32: [u8; 32] = private.scalar[..32]
                    .try_into()
                    .expect("slice is always 32 bytes");
                let px32: [u8; 32] = public.x[..32].try_into().expect("slice is always 32 bytes");
                let (result_x, _) = self.cracen_p256_mult(&scalar32, &px32, &public.y);
                scalar32.zeroize();
                let mut bytes = [0u8; 56];
                bytes[..32].copy_from_slice(&result_x);
                Ok(SharedSecret { bytes, len: 32 })
            }
            DhAlgorithm::X25519 => {
                let mut k: [u8; 32] = private.scalar[..32]
                    .try_into()
                    .expect("slice is always 32 bytes");
                clamp_x25519(&mut k);
                let mut u: [u8; 32] = public.x[..32].try_into().expect("slice is always 32 bytes");
                u[31] &= 0x7F;
                let result = self.cracen_x25519_mult(&k, &u);
                k.zeroize();
                let mut bytes = [0u8; 56];
                bytes[..32].copy_from_slice(&result);
                Ok(SharedSecret { bytes, len: 32 })
            }
            DhAlgorithm::X448 => {
                let mut k: [u8; 56] = private.scalar;
                clamp_x448(&mut k);
                let u: [u8; 56] = public.x;
                let x = self.cracen_x448_mult(&k, &u);
                k.zeroize();
                Ok(SharedSecret { bytes: x, len: 56 })
            }
        }
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private.alg {
            DhAlgorithm::EcdhP256 => {
                let mut scalar32: [u8; 32] = private.scalar[..32]
                    .try_into()
                    .expect("slice is always 32 bytes");
                let (rx, ry) = self.cracen_p256_mult(&scalar32, &P256_GX, &P256_GY);
                scalar32.zeroize();
                let mut x = [0u8; 56];
                x[..32].copy_from_slice(&rx);
                PublicKey {
                    alg: private.alg.clone(),
                    x,
                    y: ry,
                }
            }
            DhAlgorithm::X25519 => {
                let mut k: [u8; 32] = private.scalar[..32]
                    .try_into()
                    .expect("slice is always 32 bytes");
                clamp_x25519(&mut k);
                let mut base_u = [0u8; 32];
                base_u[0] = 9; // X25519 base point u-coordinate = 9 (little-endian)
                let u = self.cracen_x25519_mult(&k, &base_u);
                k.zeroize();
                let mut x = [0u8; 56];
                x[..32].copy_from_slice(&u);
                PublicKey {
                    alg: private.alg.clone(),
                    x,
                    y: [0u8; 32],
                }
            }
            DhAlgorithm::X448 => {
                let mut k: [u8; 56] = private.scalar;
                clamp_x448(&mut k);
                let mut base_u = [0u8; 56];
                base_u[0] = 5; // X448 base point u-coordinate = 5 (little-endian)
                let x = self.cracen_x448_mult(&k, &base_u);
                k.zeroize();
                PublicKey {
                    alg: private.alg.clone(),
                    x,
                    y: [0u8; 32],
                }
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
