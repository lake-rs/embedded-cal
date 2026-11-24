// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// # AES-CCM on the CryptoCell-312 AES engine
//
// CCM (RFC 3610) is computed in two passes of the AES engine:
//
// * CBC-MAC over B0, the length-prefixed AAD and the message, each zero-padded to the block size.
//   In CBC-MAC mode the engine produces no output data; the running MAC is read from AES_IV_0.
// * CTR for the message (counter blocks A1, A2, ...) and for the tag mask S0 = E(K, A0).
//
// The engine can also combine both in one tunnelled pass (as the CC312 runtime does), but the
// two-pass form needs only the basic, PS-documented modes.
//
// Register sequence after InitAes()/LoadAesKey()/LoadIVState() of the CC312 runtime. Keys, IVs and
// counters are loaded as little-endian words of their byte strings (the runtime memcpy()s the
// bytes into its word buffers).
//
// Every DMA transfer starts from a freshly loaded engine state (key, IV or counter), so no state
// needs to persist inside the engine between transfers.

use crate::{CryptoCellCal, MAX_DMA_CHUNK};
use nrf_pac::cc_aes::vals::{DecKey0, ModeKey0, NkKey0, Status};
use nrf_pac::{cc_ctl, cc_host_rgf};
use zeroize::Zeroize;

const BLOCK: usize = 16;
const TAG_LEN: usize = 8;
const NONCE_LEN: usize = 13;
/// RFC 3610 L: size of the length field, 15 - nonce length.
const L: usize = 15 - NONCE_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    AesCcm16_64_128,
    AesCcm16_64_256,
}

impl embedded_cal::AeadAlgorithm for AeadAlgorithm {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 16,
            AeadAlgorithm::AesCcm16_64_256 => 32,
        }
    }

    fn tag_length(&self) -> usize {
        TAG_LEN
    }

    fn nonce_length(&self) -> usize {
        NONCE_LEN
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            10 => Some(AeadAlgorithm::AesCcm16_64_128),
            11 => Some(AeadAlgorithm::AesCcm16_64_256),
            _ => None,
        }
    }
}

#[derive(Zeroize)]
pub enum AeadKey {
    AesCcm16_64_128([u8; 16]),
    AesCcm16_64_256([u8; 32]),
}

pub enum AeadTag {
    AesCcm16_64_128([u8; 8]),
    AesCcm16_64_256([u8; 8]),
}

impl AsRef<[u8]> for AeadTag {
    fn as_ref(&self) -> &[u8] {
        match self {
            AeadTag::AesCcm16_64_128(r) => &r[..],
            AeadTag::AesCcm16_64_256(r) => &r[..],
        }
    }
}

/// Running CBC-MAC with a buffer for an incomplete block.
struct CbcMac {
    mac: [u8; BLOCK],
    buf: [u8; BLOCK],
    fill: usize,
}

impl Drop for CbcMac {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.buf.zeroize();
    }
}

/// Adds `n` to a big-endian 128-bit counter block.
fn ctr_add(ctr: &mut [u8; BLOCK], n: usize) {
    let v = u128::from_be_bytes(*ctr).wrapping_add(n as u128);
    *ctr = v.to_be_bytes();
}

impl CryptoCellCal {
    /// Selects the AES engine and loads mode, key and IV (CBC-MAC) or counter (CTR).
    fn aes_configure(&mut self, mode: ModeKey0, key: &[u8], iv: &[u8; BLOCK]) {
        self.wait_crypto_idle();
        self.cc_host_rgf
            .icr()
            .write_value(cc_host_rgf::regs::Icr(0xFFFF_FFFF));

        self.cc_ctl
            .crypto_ctl()
            .write(|w| w.set_mode(cc_ctl::vals::Mode::AesActive));
        self.cc_aes.aes_remaining_bytes().write_value(0);
        self.cc_aes.aes_control().write(|w| {
            // Both CBC-MAC and CTR only ever use the forward cipher.
            w.set_dec_key0(DecKey0::Encrypt);
            w.set_mode_key0(mode);
            w.set_nk_key0(match key.len() {
                16 => NkKey0::_128bits,
                32 => NkKey0::_256bits,
                _ => unreachable!("key length checked at load time"),
            });
        });

        for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
            self.cc_aes
                .aes_key_0(i)
                .write_value(u32::from_le_bytes(*word));
        }
        for (i, word) in iv.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_le_bytes(*word);
            match mode {
                ModeKey0::Ctr => self.cc_aes.aes_ctr(i).write_value(word),
                _ => self.cc_aes.aes_iv_0(i).write_value(word),
            }
        }
    }

    fn aes_wait_idle(&self) {
        while self.cc_aes.aes_busy().read().status() == Status::Busy {}
    }

    /// Runs CBC-MAC over whole blocks of `data`, continuing from (and updating) `mac`.
    fn cbc_mac_blocks(&mut self, key: &[u8], mac: &mut [u8; BLOCK], data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(BLOCK));
        for chunk in data.chunks(MAX_DMA_CHUNK) {
            self.aes_configure(ModeKey0::CbcMac, key, mac);
            self.dma_in(chunk);
            self.aes_wait_idle();
            for (i, out) in mac.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *out = self.cc_aes.aes_iv_0(i).read().to_le_bytes();
            }
        }
    }

    /// Feeds bytes into a running CBC-MAC; whole blocks are DMA'd from `data` directly.
    fn cbc_mac_absorb(&mut self, key: &[u8], st: &mut CbcMac, mut data: &[u8]) {
        if st.fill > 0 {
            let take = (BLOCK - st.fill).min(data.len());
            st.buf[st.fill..st.fill + take].copy_from_slice(&data[..take]);
            st.fill += take;
            data = &data[take..];
            if st.fill == BLOCK {
                self.cbc_mac_blocks(key, &mut st.mac, &st.buf);
                st.fill = 0;
            }
        }

        let whole = data.len() & !(BLOCK - 1);
        if whole > 0 {
            self.cbc_mac_blocks(key, &mut st.mac, &data[..whole]);
            data = &data[whole..];
        }

        if !data.is_empty() {
            // An incompletely filled buffer has absorbed all of `data` above.
            st.buf[..data.len()].copy_from_slice(data);
            st.fill = data.len();
        }
    }

    /// Zero-pads and processes any buffered partial block.
    fn cbc_mac_pad(&mut self, key: &[u8], st: &mut CbcMac) {
        if st.fill > 0 {
            st.buf[st.fill..].fill(0);
            self.cbc_mac_blocks(key, &mut st.mac, &st.buf);
            st.fill = 0;
        }
    }

    /// XORs `data` in place with the AES-CTR keystream starting at counter block `ctr`.
    fn ctr_in_place(&mut self, key: &[u8], ctr: &[u8; BLOCK], data: &mut [u8]) {
        let mut ctr = *ctr;
        let whole = data.len() & !(BLOCK - 1);
        let (blocks, tail) = data.split_at_mut(whole);

        for chunk in blocks.chunks_mut(MAX_DMA_CHUNK) {
            self.aes_configure(ModeKey0::Ctr, key, &ctr);
            self.dma_in_place(chunk);
            self.aes_wait_idle();
            ctr_add(&mut ctr, chunk.len() / BLOCK);
        }

        if !tail.is_empty() {
            let mut block = [0u8; BLOCK];
            block[..tail.len()].copy_from_slice(tail);
            self.aes_configure(ModeKey0::Ctr, key, &ctr);
            self.dma_in_place(&mut block);
            self.aes_wait_idle();
            tail.copy_from_slice(&block[..tail.len()]);
            block.zeroize();
        }
    }

    /// CCM authentication tag (before masking with S0) over AAD and plaintext.
    fn ccm_mac(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &impl embedded_cal::AadGenerator,
    ) -> CbcMac {
        let aad_len: usize = aad.items().map(|c| c.len()).sum();
        // Longer AAD would need the 6-byte length encoding of RFC 3610.
        assert!(aad_len < 0xFF00, "AAD too long");

        let mut st = CbcMac {
            mac: [0; BLOCK],
            buf: [0; BLOCK],
            fill: 0,
        };
        let b0 = embedded_cal::util::aesccm::build_b0(nonce, plaintext.len(), aad_len, TAG_LEN);
        self.cbc_mac_absorb(key, &mut st, &b0);
        if aad_len > 0 {
            self.cbc_mac_absorb(key, &mut st, &(aad_len as u16).to_be_bytes());
            for chunk in aad.items() {
                self.cbc_mac_absorb(key, &mut st, chunk);
            }
            self.cbc_mac_pad(key, &mut st);
        }
        self.cbc_mac_absorb(key, &mut st, plaintext);
        self.cbc_mac_pad(key, &mut st);
        st
    }

    /// Counter block A_i (RFC 3610 2.3) for i = 0.
    fn ccm_a0(nonce: &[u8]) -> [u8; BLOCK] {
        let mut a0 = [0u8; BLOCK];
        a0[0] = (L - 1) as u8;
        a0[1..1 + NONCE_LEN].copy_from_slice(nonce);
        a0
    }

    /// Masks the raw CBC-MAC with S0 = E(K, A0), yielding the tag.
    fn ccm_tag(&mut self, key: &[u8], a0: &[u8; BLOCK], st: &CbcMac) -> [u8; TAG_LEN] {
        let mut s0 = [0u8; BLOCK];
        self.ctr_in_place(key, a0, &mut s0);
        let mut tag = [0u8; TAG_LEN];
        for (t, (m, s)) in tag.iter_mut().zip(st.mac.iter().zip(s0)) {
            *t = m ^ s;
        }
        s0.zeroize();
        tag
    }

    fn ccm_encrypt<const KEY_LEN: usize>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> [u8; TAG_LEN] {
        const {
            assert!(
                KEY_LEN == 16 || KEY_LEN == 32,
                "AES-CCM key must be 16 (AES-128) or 32 (AES-256) bytes"
            )
        };
        assert_eq!(nonce.len(), NONCE_LEN, "nonce length mismatch");
        assert!(
            message.len() < 1 << (8 * L),
            "message too long for CCM with L=2"
        );

        let st = self.ccm_mac(key, nonce, message, &aad);
        let mut ctr = Self::ccm_a0(nonce);
        let tag = self.ccm_tag(key, &ctr, &st);

        ctr_add(&mut ctr, 1);
        self.ctr_in_place(key, &ctr, message);
        tag
    }

    fn ccm_decrypt<const KEY_LEN: usize>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8],
        ciphertext: &mut [u8],
        tag_in: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> bool {
        const {
            assert!(
                KEY_LEN == 16 || KEY_LEN == 32,
                "AES-CCM key must be 16 (AES-128) or 32 (AES-256) bytes"
            )
        };
        assert_eq!(nonce.len(), NONCE_LEN, "nonce length mismatch");
        assert_eq!(tag_in.len(), TAG_LEN, "tag length mismatch");
        assert!(
            ciphertext.len() < 1 << (8 * L),
            "message too long for CCM with L=2"
        );

        let a0 = Self::ccm_a0(nonce);
        let mut ctr = a0;
        ctr_add(&mut ctr, 1);
        self.ctr_in_place(key, &ctr, ciphertext);

        let st = self.ccm_mac(key, nonce, ciphertext, &aad);
        let tag = self.ccm_tag(key, &a0, &st);

        // Constant-time comparison
        let diff = tag
            .iter()
            .zip(tag_in)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        let mac_ok = diff == 0;
        if !mac_ok {
            // Do not leave unauthenticated plaintext around.
            ciphertext.zeroize();
        }
        mac_ok
    }
}

impl embedded_cal::AeadProvider for super::CryptoCellCal {
    type Algorithm = AeadAlgorithm;
    type Key = AeadKey;
    type Tag = AeadTag;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::AesCcm16_64_128 => {
                AeadKey::AesCcm16_64_128(key.try_into().expect("key length mismatch"))
            }
            AeadAlgorithm::AesCcm16_64_256 => {
                AeadKey::AesCcm16_64_256(key.try_into().expect("key length mismatch"))
            }
        }
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        match key {
            AeadKey::AesCcm16_64_128(key_bytes) => {
                AeadTag::AesCcm16_64_128(self.ccm_encrypt(key_bytes, nonce, message, aad))
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                AeadTag::AesCcm16_64_256(self.ccm_encrypt(key_bytes, nonce, message, aad))
            }
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        cyphertext: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        let ok = match key {
            AeadKey::AesCcm16_64_128(key_bytes) => {
                self.ccm_decrypt(key_bytes, nonce, cyphertext, tag, aad)
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                self.ccm_decrypt(key_bytes, nonce, cyphertext, tag, aad)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(embedded_cal::DecryptionFailed)
        }
    }
}
