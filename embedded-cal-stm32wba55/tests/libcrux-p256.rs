// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]
#![no_main]

use defmt_rtt as _;
use embedded_alloc::LlffHeap as Heap;
use embedded_cal::plumbing::ec::P256;
use embedded_cal_stm32wba55::Stm32wba55Cal;
use panic_probe as _;
use testvectors::dh::EccVector;

// XXX: `libcrux-iot-p256` still depends on a version of `libcrux-hacl-rs`
// that needs a global allocator.
#[global_allocator]
static HEAP: Heap = Heap::empty();

struct TestState {
    board_cal: Stm32wba55Cal,
}

#[defmt_test::tests]
mod tests {
    use embedded_cal::plumbing::ec::Ec;
    use testvectors::dh::RFC5903_P256;

    use crate::{HEAP, LibcruxTestVector};

    #[init]
    fn init() -> super::TestState {
        let board_cal = embedded_cal_stm32wba55::Stm32wba55Cal::new(
            stm32_metapac::HASH,
            stm32_metapac::RCC,
            stm32_metapac::RNG,
            stm32_metapac::AES,
            stm32_metapac::PKA,
        );
        // Initialize the heap
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE) }

        super::TestState { board_cal }
    }

    #[test]
    fn test_ecc_p256(state: &mut super::TestState) {
        let ec = state.board_cal.p256();

        for v in RFC5903_P256 {
            LibcruxTestVector(v).libcrux_test_with(ec);
        }
    }
}

struct LibcruxTestVector<'a>(&'a EccVector);
impl<'a> LibcruxTestVector<'a> {
    /// Runs the test vector by the Cal implementation.
    ///
    /// Panics if either the algorithm is not supported, or either direction of running DH does not
    /// result in the expected shared secret.
    pub fn libcrux_test_with<C: embedded_cal::plumbing::ec::EcPrimitives<P256>>(&self, ec: &mut C) {
        let mut alice_public_computed = [0u8; 64];
        assert!(libcrux_iot_p256::embedded_cal_integration::dh_initiator_ec(
            ec,
            &mut alice_public_computed,
            self.0.alice_private
        ));
        assert_eq!(self.0.alice_public, &alice_public_computed[..32]);

        let mut bob_public_computed = [0u8; 64];
        assert!(libcrux_iot_p256::embedded_cal_integration::dh_initiator_ec(
            ec,
            bob_public_computed.as_mut_slice(),
            self.0.bob_private
        ));
        assert_eq!(self.0.bob_public, &bob_public_computed[..32]);

        let mut alice_shared_secret = [0u8; 64];
        assert!(libcrux_iot_p256::embedded_cal_integration::dh_responder_ec(
            ec,
            alice_shared_secret.as_mut_slice(),
            &bob_public_computed,
            self.0.alice_private,
        ));
        assert_eq!(&alice_shared_secret[..32], self.0.shared_secret);

        let mut bob_shared_secret = [0u8; 64];
        assert!(libcrux_iot_p256::embedded_cal_integration::dh_responder_ec(
            ec,
            bob_shared_secret.as_mut_slice(),
            &alice_public_computed,
            self.0.bob_private,
        ));
        assert_eq!(&bob_shared_secret[..32], self.0.shared_secret);
    }
}
