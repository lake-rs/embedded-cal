// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// # BA411E AES engine — cryptomaster DMA tags and command words
//
// Sources: sdk-nrf subsys/nrf_security/src/drivers/cracen/sxsymcrypt/src/{cmdma.h,cmaes.h,aead.c}
//
// DMATAG layout (input descriptors only; the pusher ignores dmatag on output descriptors):
//   bits [3:0]  — engine selector  (DMATAG_BA411 = 1)
//   bit    [4]  — config-register write flag  (DMATAG_CONFIG sets this)
//   bit    [6]  — header/AAD data type flag   (DMATAG_DATATYPE_HEADER)
//   bits [12:8] — trailing padding bytes to ignore  (DMATAG_IGN, see descriptor::dmatag_ign)
//   bits [15:8] — config register offset when bit 4 is set

const DMATAG_BA411: u32 = 1;

// Config-register descriptors (bit 4 set; register offset in bits [15:8]):
const DMATAG_AES_CFG: u32 = DMATAG_BA411 | (1 << 4); // offset 0x00 → 0x0011
const DMATAG_AES_KEY: u32 = DMATAG_BA411 | (1 << 4) | (0x08 << 8); // offset 0x08 → 0x0811

// Data descriptors:
const DMATAG_AES_AAD: u32 = DMATAG_BA411 | (1 << 6); // DATATYPE_HEADER → 0x0041
const DMATAG_AES_DATA: u32 = DMATAG_BA411; // plaintext / ciphertext / tag → 0x0001

// Command words written as the first input descriptor (dmatag = DMATAG_AES_CFG):
//   bits [15:8] — mode: 1 << (8 + mode_id); CCM mode_id = 5 → bit 13 → 0x2000
//   bit     [0] — direction: 0 = encrypt, 1 = decrypt
// Key size is NOT encoded here — the BA411E infers it from the byte count of the
// key descriptor (16 bytes → AES-128, 32 bytes → AES-256).
const AES_CCM_MODE: u32 = 1 << 13; // CMDMA_AEAD_MODE_SET(5)
const AES_CMD_CCM_ENCRYPT: u32 = AES_CCM_MODE; // 0x2000
const AES_CMD_CCM_DECRYPT: u32 = AES_CCM_MODE | 1; // 0x2001

use crate::descriptor::{DescriptorChain, Input, Output, dmatag_ign};

/// Pushes the CCM header (the `DMATAG_AES_AAD` descriptors) onto `input_chain`: B0, then — when
/// AAD is present — the 2-byte big-endian length prefix, the AAD chunks streamed straight from the
/// caller, and the trailing CCM zero-pad.
///
/// Every descriptor up to the last AAD-type one is RAW (no realign) so the fetcher carries sub-word
/// remainders straight into the next descriptor, keeping the CBC-MAC byte stream contiguous. The
/// final AAD-type descriptor must use `push` (realign) so the engine flushes the block before the
/// message data: that is the zero-pad when the header is not block-aligned, otherwise the last AAD
/// chunk itself.
///
/// `header_pad` is the zero-padding slice already trimmed to its length (`header_ign` bytes, 0..16);
/// its length doubles as the ignore count for the final descriptor.
fn push_ccm_header<'mem, const N: usize>(
    input_chain: &mut DescriptorChain<'mem, Input, N>,
    b0: &'mem [u8],
    aad_len: usize,
    aad_len_prefix: &'mem [u8],
    aad: &'mem impl embedded_cal::AadGenerator,
    header_pad: &'mem [u8],
) {
    input_chain.push(b0, DMATAG_AES_AAD);
    if aad_len == 0 {
        return;
    }
    let header_ign = header_pad.len();
    input_chain.push_raw(aad_len_prefix, DMATAG_AES_AAD);
    let mut chunks = aad.items().filter(|c| !c.is_empty()).peekable();
    while let Some(chunk) = chunks.next() {
        if chunks.peek().is_none() && header_ign == 0 {
            // Last AAD-type descriptor: it MUST realign, so use `push` (not `push_raw`).
            input_chain.push(chunk, DMATAG_AES_AAD);
        } else {
            input_chain.push_raw(chunk, DMATAG_AES_AAD);
        }
    }
    if header_ign > 0 {
        input_chain.push(header_pad, DMATAG_AES_AAD | dmatag_ign(header_ign));
    }
}

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
        8
    }

    fn nonce_length(&self) -> usize {
        13
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            10 => Some(AeadAlgorithm::AesCcm16_64_128),
            11 => Some(AeadAlgorithm::AesCcm16_64_256),
            _ => None,
        }
    }
}

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

impl super::Nrf54l15Cal {
    fn ccm_encrypt<const KEY_LEN: usize>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> [u8; 8] {
        const {
            assert!(
                KEY_LEN == 16 || KEY_LEN == 32,
                "AES-CCM key must be 16 (AES-128) or 32 (AES-256) bytes"
            )
        };
        const TAG_LEN: usize = 8;
        let cmd = AES_CMD_CCM_ENCRYPT.to_le_bytes();

        let mut aad_len = 0usize;
        for chunk in aad.items() {
            aad_len += chunk.len();
        }
        let b0 = embedded_cal::build_b0(nonce, message.len(), aad_len, TAG_LEN);
        let aad_len_prefix = [(aad_len >> 8) as u8, (aad_len & 0xFF) as u8];
        let header_pad = [0u8; 16];
        let header_data_len = if aad_len == 0 { 16 } else { 18 + aad_len };
        let header_padded_len = (header_data_len + 15) & !15;
        let header_ign = header_padded_len - header_data_len;

        // Plaintext, zero-padded to 16-byte multiple; max 255 B → 256 B.
        let msg_padded_len = (message.len() + 15) & !15;
        let msg_ign = msg_padded_len - message.len();
        let mut msg_in_buf = [0u8; 256];
        msg_in_buf[..message.len()].copy_from_slice(message);

        let mut ct_buf = [0u8; 256];
        let mut tag_out_buf = [0u8; 16];
        // The BA411E emits one output byte per header input byte (intermediate
        // CBC-MAC state). Absorb those into a scratch buffer so that ct_buf and
        // tag_out_buf receive the correct ciphertext and tag.
        let mut b0_out_buf = [0u8; 16];
        // One output byte per header input byte after B0: aad_len (2 B) + aad + zero-pad =
        // header_padded_len - 16 B (max 288 - 16 = 272). Output count matches input exactly.
        let mut header_aad_out_buf = [0u8; 272];

        let mut input_chain: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        let mut output_chain: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();

        input_chain.push(&cmd, DMATAG_AES_CFG);
        input_chain.push(key, DMATAG_AES_KEY);
        push_ccm_header(
            &mut input_chain,
            &b0,
            aad_len,
            &aad_len_prefix,
            &aad,
            &header_pad[..header_ign],
        );
        if !message.is_empty() {
            input_chain.push(
                &msg_in_buf[..msg_padded_len],
                DMATAG_AES_DATA | dmatag_ign(msg_ign),
            );
        }
        output_chain.push(&mut b0_out_buf, 0);
        if aad_len > 0 {
            output_chain.push(&mut header_aad_out_buf[..header_padded_len - 16], 0);
        }
        if !message.is_empty() {
            output_chain.push(&mut ct_buf[..msg_padded_len], 0);
        }
        output_chain.push(&mut tag_out_buf, 0);

        self.execute_cryptomaster_dma(&mut input_chain, &mut output_chain);

        message.copy_from_slice(&ct_buf[..message.len()]);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&tag_out_buf[..TAG_LEN]);
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
        const TAG_LEN: usize = 8;
        let cmd = AES_CMD_CCM_DECRYPT.to_le_bytes();

        // See `ccm_encrypt` for the header layout; the AAD is streamed straight from the caller's
        // chunks, with only B0, the length prefix, and the zero-pad in local buffers.
        let mut aad_len = 0usize;
        for chunk in aad.items() {
            aad_len += chunk.len();
        }
        let b0 = embedded_cal::build_b0(nonce, ciphertext.len(), aad_len, TAG_LEN);
        let aad_len_prefix = [(aad_len >> 8) as u8, (aad_len & 0xFF) as u8];
        let header_pad = [0u8; 16];
        let header_data_len = if aad_len == 0 { 16 } else { 18 + aad_len };
        let header_padded_len = (header_data_len + 15) & !15;
        let header_ign = header_padded_len - header_data_len;

        let ct_padded_len = (ciphertext.len() + 15) & !15;
        let ct_ign = ct_padded_len - ciphertext.len();
        let mut ct_in_buf = [0u8; 256];
        ct_in_buf[..ciphertext.len()].copy_from_slice(ciphertext);

        // Expected tag padded to 16 B; engine outputs XOR(computed_tag, expected_tag).
        // All-zero output means the tags match.
        let mut tag_in_buf = [0u8; 16];
        tag_in_buf[..TAG_LEN].copy_from_slice(&tag_in[..TAG_LEN]);

        let mut pt_buf = [0u8; 256];
        let mut xor_tag_buf = [0u8; 16];
        let mut header_out_buf = [0u8; 288];

        let mut input_chain: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        let mut output_chain: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();

        input_chain.push(&cmd, DMATAG_AES_CFG);
        input_chain.push(key, DMATAG_AES_KEY);
        push_ccm_header(
            &mut input_chain,
            &b0,
            aad_len,
            &aad_len_prefix,
            &aad,
            &header_pad[..header_ign],
        );
        if !ciphertext.is_empty() {
            input_chain.push(
                &ct_in_buf[..ct_padded_len],
                DMATAG_AES_DATA | dmatag_ign(ct_ign),
            );
        }
        input_chain.push(&tag_in_buf, DMATAG_AES_DATA | dmatag_ign(16 - TAG_LEN));
        output_chain.push(&mut header_out_buf[..header_padded_len], 0);
        if !ciphertext.is_empty() {
            output_chain.push(&mut pt_buf[..ct_padded_len], 0);
        }
        output_chain.push(&mut xor_tag_buf, 0);

        self.execute_cryptomaster_dma(&mut input_chain, &mut output_chain);

        let mac_ok = xor_tag_buf[..TAG_LEN].iter().all(|&b| b == 0);
        if mac_ok {
            ciphertext.copy_from_slice(&pt_buf[..ciphertext.len()]);
        }
        mac_ok
    }
}

impl embedded_cal::AeadProvider for super::Nrf54l15Cal {
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
