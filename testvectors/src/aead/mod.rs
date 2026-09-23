// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
pub mod aes_ccm;
pub mod aes_gcm;

use embedded_cal::{AeadAlgorithm, AeadProvider, Cal, accessor::*};

struct KnownAlgorithm {
    alg_cose: i16,
    tag_length: usize,
    key_length: usize,
    nonce_length: usize,
}

impl KnownAlgorithm {
    fn construct<C: Cal>(&self, _cal: &mut C) -> AeadAlgorithmOf<C> {
        let Some(alg) = AeadAlgorithmOf::<C>::from_cose_number(self.alg_cose) else {
            panic!("expected algorithm could not be constructed by Cal");
        };
        alg
    }

    /// Builds the algorithm for the Cal and tests whether it has the expected lengths.
    fn test_properties<C: Cal>(&self, cal: &mut C) {
        // If we grow more constructors, this will also test their equivalence.

        let alg = self.construct(cal);
        assert_eq!(alg.tag_length(), self.tag_length);
        assert_eq!(alg.key_length(), self.key_length);
        assert_eq!(alg.nonce_length(), self.nonce_length);
    }
}

struct AeadCase {
    alg: &'static KnownAlgorithm,
    key: &'static [u8],
    nonce: &'static [u8],
    // The tester will chunk this up arbitrarily
    aad: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
    tag: &'static [u8],
}

impl AeadCase {
    fn test_with_chunker<Cal: embedded_cal::Cal>(
        &self,
        cal: &mut Cal,
        aad: impl embedded_cal::AadGenerator + Copy,
    ) {
        let alg = self.alg.construct(cal);
        // Sanity checks for test vector authors
        assert_eq!(
            self.alg.key_length,
            self.key.len(),
            "Test key is not of the exepected shape"
        );
        assert_eq!(
            self.alg.tag_length,
            self.tag.len(),
            "Test tag is not of the exepected shape"
        );
        assert_eq!(
            self.alg.nonce_length,
            self.nonce.len(),
            "Test nonce is not of the exepected shape"
        );

        let cal = cal.aead();

        let key = cal.load_from_keydata(alg, self.key);

        let mut buf = [0; 4096];
        let buf = &mut buf[..self.plaintext.len()];
        buf.copy_from_slice(self.plaintext);

        // FIXME: assert aad == self.aad

        let produced_tag = cal.encrypt_in_place(&key, self.nonce, buf, aad);
        assert_eq!(
            produced_tag.as_ref(),
            self.tag,
            "tag mismatch: expected {:02x?}, got {:02x?}",
            self.tag,
            produced_tag.as_ref()
        );
        assert_eq!(
            buf, self.ciphertext,
            "ciphertext mismatch: expected {:02x?}, got {:02x?}",
            self.ciphertext, buf
        );

        cal.decrypt_in_place(&key, self.nonce, buf, self.tag, aad)
            .unwrap();
        assert_eq!(
            buf, self.plaintext,
            "decryption mismatch: expected {:02x?}, got {:02x?}",
            self.plaintext, buf
        );
    }

    fn test<Cal: embedded_cal::Cal>(&self, cal: &mut Cal) {
        self.test_with_chunker(cal, self.aad);

        // FIXME: Which chunkings make sense?
        for firstpart in [1, 15, 16, 17] {
            if self.aad.len() > firstpart {
                self.test_with_chunker(
                    cal,
                    [&self.aad[..firstpart], &self.aad[firstpart..]].as_slice(),
                );
            }
        }
    }
}
