// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

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
            AeadTag::AesCcm16_64_128(r) => r,
            AeadTag::AesCcm16_64_256(r) => r,
        }
    }
}

/// Feed one 16-byte block into the AES DINR and wait for CCF, then clear it.
fn feed_block(aes: &stm32_metapac::aes::Aes, block: &[u8; 16]) {
    for i in 0..4 {
        aes.dinr().write_value(u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]));
    }
    while !aes.isr().read().ccf() {}
    aes.isr().write(|w| w.set_ccf(true));
}

/// Write a 16-byte block into AES_IVR3..AES_IVR0 (MSB-first, big-endian words).
fn write_ivr(aes: &stm32_metapac::aes::Aes, block: &[u8; 16]) {
    aes.ivr(3)
        .write_value(u32::from_be_bytes([block[0], block[1], block[2], block[3]]));
    aes.ivr(2)
        .write_value(u32::from_be_bytes([block[4], block[5], block[6], block[7]]));
    aes.ivr(1).write_value(u32::from_be_bytes([
        block[8], block[9], block[10], block[11],
    ]));
    aes.ivr(0).write_value(u32::from_be_bytes([
        block[12], block[13], block[14], block[15],
    ]));
}

/// Write a 256-bit key into AES_KEYR7..AES_KEYR0 (MSB-first, big-endian words).
fn write_key_256(aes: &stm32_metapac::aes::Aes, key: &[u8; 32]) {
    aes.keyr(7)
        .write_value(u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
    aes.keyr(6)
        .write_value(u32::from_be_bytes([key[4], key[5], key[6], key[7]]));
    aes.keyr(5)
        .write_value(u32::from_be_bytes([key[8], key[9], key[10], key[11]]));
    aes.keyr(4)
        .write_value(u32::from_be_bytes([key[12], key[13], key[14], key[15]]));
    aes.keyr(3)
        .write_value(u32::from_be_bytes([key[16], key[17], key[18], key[19]]));
    aes.keyr(2)
        .write_value(u32::from_be_bytes([key[20], key[21], key[22], key[23]]));
    aes.keyr(1)
        .write_value(u32::from_be_bytes([key[24], key[25], key[26], key[27]]));
    aes.keyr(0)
        .write_value(u32::from_be_bytes([key[28], key[29], key[30], key[31]]));
}

/// Write a 128-bit key into AES_KEYR3..AES_KEYR0 (MSB-first, big-endian words).
fn write_key_128(aes: &stm32_metapac::aes::Aes, key: &[u8; 16]) {
    aes.keyr(3)
        .write_value(u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
    aes.keyr(2)
        .write_value(u32::from_be_bytes([key[4], key[5], key[6], key[7]]));
    aes.keyr(1)
        .write_value(u32::from_be_bytes([key[8], key[9], key[10], key[11]]));
    aes.keyr(0)
        .write_value(u32::from_be_bytes([key[12], key[13], key[14], key[15]]));
}

/// Run the CCM final phase: set GCMPH, wait for CCF, drain DOUTR, clear CCF, disable EN.
/// Returns the raw 16-byte authentication tag produced by the hardware.
fn run_final_phase(aes: &stm32_metapac::aes::Aes) -> [u8; 16] {
    use stm32_metapac::aes::vals::Gcmph;
    aes.cr().modify(|w| w.set_gcmph(Gcmph::FINAL_PHASE));
    while !aes.isr().read().ccf() {}

    let mut tag_full = [0u8; 16];
    for i in 0..4 {
        let word: u32 = aes.doutr().read();
        tag_full[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    aes.isr().write(|w| w.set_ccf(true));
    aes.cr().modify(|w| w.set_en(false));
    tag_full
}

/// Write a 16-byte block to AES_DINR, wait for CCF, read the output from AES_DOUTR,
/// clear CCF, and return the output block.
fn exchange_block(aes: &stm32_metapac::aes::Aes, block: &[u8; 16]) -> [u8; 16] {
    for i in 0..4 {
        aes.dinr().write_value(u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]));
    }
    while !aes.isr().read().ccf() {}

    let mut out = [0u8; 16];
    for i in 0..4 {
        let word: u32 = aes.doutr().read();
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    aes.isr().write(|w| w.set_ccf(true));
    out
}

/// Run the CCM payload phase: set GCMPH, enable, and process message in place.
/// When `with_npblb` is true (decryption), sets NPBLB on the last partial block so the
/// hardware zeros padding bytes before feeding them into the CBC-MAC.
fn run_payload_phase(aes: &stm32_metapac::aes::Aes, message: &mut [u8], with_npblb: bool) {
    use stm32_metapac::aes::vals::Gcmph;
    aes.cr().modify(|w| w.set_gcmph(Gcmph::PAYLOAD_PHASE));
    aes.cr().modify(|w| w.set_en(true));

    let msg_len = message.len();
    let mut msg_offset = 0;
    while msg_offset < msg_len {
        let mut block = [0u8; 16];
        let chunk = (msg_len - msg_offset).min(16);
        block[..chunk].copy_from_slice(&message[msg_offset..msg_offset + chunk]);

        if with_npblb {
            let is_last = msg_offset + chunk >= msg_len;
            if is_last && chunk < 16 {
                aes.cr().modify(|w| w.set_npblb((16 - chunk) as u8));
            }
        }

        let out = exchange_block(aes, &block);
        message[msg_offset..msg_offset + chunk].copy_from_slice(&out[..chunk]);
        msg_offset += chunk;
    }
}

/// Run the CCM init phase for a 256-bit key.
fn run_init_phase_256(
    aes: &stm32_metapac::aes::Aes,
    mode: stm32_metapac::aes::vals::Mode,
    nonce: &[u8],
    msg_len: usize,
    a_len: usize,
    tag_len: usize,
    key: &[u8; 32],
) {
    use stm32_metapac::aes::vals::{Chmod, Datatype, Gcmph};
    aes.cr().modify(|w| w.set_en(false));
    aes.cr().modify(|w| {
        w.set_chmod(Chmod::CCM);
        w.set_datatype(Datatype::NONE);
        w.set_keysize(true); // 256-bit key
        w.set_mode(mode);
        w.set_kmod(0x00);
        w.set_gcmph(Gcmph::INIT_PHASE);
        w.set_npblb(0);
    });

    write_ivr(aes, &embedded_cal::build_b0(nonce, msg_len, a_len, tag_len));
    write_key_256(aes, key);

    while !aes.sr().read().keyvalid() {}
    aes.cr().modify(|w| w.set_en(true));
    while !aes.isr().read().ccf() {}
    aes.isr().write(|w| w.set_ccf(true));
}

/// Run the CCM init phase for a 128-bit key: configure AES_CR, load B0 and key,
/// enable the peripheral, and wait for the first mask computation to complete.
fn run_init_phase_128(
    aes: &stm32_metapac::aes::Aes,
    mode: stm32_metapac::aes::vals::Mode,
    nonce: &[u8],
    msg_len: usize,
    a_len: usize,
    tag_len: usize,
    key: &[u8; 16],
) {
    use stm32_metapac::aes::vals::{Chmod, Datatype, Gcmph};
    aes.cr().modify(|w| w.set_en(false));
    aes.cr().modify(|w| {
        w.set_chmod(Chmod::CCM);
        w.set_datatype(Datatype::NONE);
        w.set_keysize(false); // 128-bit key
        w.set_mode(mode);
        w.set_kmod(0x00);
        w.set_gcmph(Gcmph::INIT_PHASE);
        w.set_npblb(0); // clear stale NPBLB from any previous operation
    });

    write_ivr(aes, &embedded_cal::build_b0(nonce, msg_len, a_len, tag_len));
    write_key_128(aes, key);

    while !aes.sr().read().keyvalid() {}
    aes.cr().modify(|w| w.set_en(true));
    while !aes.isr().read().ccf() {}
    aes.isr().write(|w| w.set_ccf(true));
}

/// Run the CCM header phase: feed [len_hi, len_lo, aad...] in 16-byte blocks.
/// Must be called only when a_len > 0 (i.e. there is AAD to authenticate).
fn run_header_phase(
    aes: &stm32_metapac::aes::Aes,
    aad: impl embedded_cal::AadGenerator,
    a_len: usize,
) {
    use stm32_metapac::aes::vals::Gcmph;
    aes.cr().modify(|w| w.set_gcmph(Gcmph::HEADER_PHASE));
    aes.cr().modify(|w| w.set_en(true));

    let mut block = [0u8; 16];
    // 2-byte length encoding (covers a_len < 0xFF00)
    block[0] = (a_len >> 8) as u8;
    block[1] = (a_len & 0xFF) as u8;
    let mut pos = 2usize;

    for slice in aad.items() {
        let mut slice_offset = 0;
        while slice_offset < slice.len() {
            let n = (slice.len() - slice_offset).min(16 - pos);
            block[pos..pos + n].copy_from_slice(&slice[slice_offset..slice_offset + n]);
            pos += n;
            slice_offset += n;
            if pos == 16 {
                feed_block(aes, &block);
                block = [0u8; 16];
                pos = 0;
            }
        }
    }
    if pos > 0 {
        // Partial last block, already zero-padded by array initialization.
        feed_block(aes, &block);
    }
}

impl embedded_cal::AeadProvider for super::Stm32wba55Cal {
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
        use stm32_metapac::aes::vals::Mode;

        match key {
            AeadKey::AesCcm16_64_128(key_bytes) => {
                // Follows the "CCM encryption and decryption process" from RM0493 (STM32WBA5x
                // Reference Manual), which runs four sequential hardware phases:
                // init → header → payload → final.
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                // Total AAD length is needed for B0 Adata flag and B1 length prefix.
                let a_len: usize = aad.items().map(|s| s.len()).sum();

                // init phase
                run_init_phase_128(
                    aes,
                    Mode::MODE1,
                    nonce,
                    message.len(),
                    a_len,
                    TAG_LEN,
                    key_bytes,
                );

                // header phase
                if a_len > 0 {
                    run_header_phase(aes, aad, a_len);
                }

                // payload phase
                run_payload_phase(aes, message, false);

                // final phase
                let tag_full = run_final_phase(aes);

                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&tag_full[..TAG_LEN]);
                AeadTag::AesCcm16_64_128(tag)
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                let a_len: usize = aad.items().map(|s| s.len()).sum();

                run_init_phase_256(
                    aes,
                    Mode::MODE1,
                    nonce,
                    message.len(),
                    a_len,
                    TAG_LEN,
                    key_bytes,
                );

                if a_len > 0 {
                    run_header_phase(aes, aad, a_len);
                }

                run_payload_phase(aes, message, false);

                let tag_full = run_final_phase(aes);

                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&tag_full[..TAG_LEN]);
                AeadTag::AesCcm16_64_256(tag)
            }
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        use stm32_metapac::aes::vals::Mode;

        match key {
            AeadKey::AesCcm16_64_128(key_bytes) => {
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                let a_len: usize = aad.items().map(|s| s.len()).sum();

                // init phase
                run_init_phase_128(
                    aes,
                    Mode::MODE3,
                    nonce,
                    message.len(),
                    a_len,
                    TAG_LEN,
                    key_bytes,
                );

                // header phase
                if a_len > 0 {
                    run_header_phase(aes, aad, a_len);
                }

                // payload phase
                run_payload_phase(aes, message, true);

                // final phase
                let tag_full = run_final_phase(aes);

                let computed = &tag_full[..TAG_LEN];
                let tags_match = computed.len() == tag.len()
                    && computed
                        .iter()
                        .zip(tag.iter())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0;

                if tags_match {
                    Ok(())
                } else {
                    Err(embedded_cal::DecryptionFailed)
                }
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                let a_len: usize = aad.items().map(|s| s.len()).sum();

                run_init_phase_256(
                    aes,
                    Mode::MODE3,
                    nonce,
                    message.len(),
                    a_len,
                    TAG_LEN,
                    key_bytes,
                );

                if a_len > 0 {
                    run_header_phase(aes, aad, a_len);
                }

                run_payload_phase(aes, message, true);

                let tag_full = run_final_phase(aes);

                let computed = &tag_full[..TAG_LEN];
                let tags_match = computed.len() == tag.len()
                    && computed
                        .iter()
                        .zip(tag.iter())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0;

                if tags_match {
                    Ok(())
                } else {
                    Err(embedded_cal::DecryptionFailed)
                }
            }
        }
    }
}
