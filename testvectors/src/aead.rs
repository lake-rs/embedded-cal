pub mod aes_ccm;

pub struct AeadCase {
    alg_cose: i16,
    key: &'static [u8],
    nonce: &'static [u8],
    // The tester will chunk this up arbitrarily
    aad: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
    tag: &'static [u8],
}

impl AeadCase {
    fn test<Cal: embedded_cal::AeadProvider>(&self, cal: &mut Cal) {
        use embedded_cal::AeadAlgorithm;

        let alg = Cal::Algorithm::from_cose_number(self.alg_cose)
            .expect("algorithm not present for test");

        let key = cal.load_from_keydata(alg, self.key);

        let mut buf = [0; 4096];
        let buf = &mut buf[..self.plaintext.len()];
        buf.copy_from_slice(self.plaintext);

        // FIXME: try again with chunked AAD

        let produced_tag = cal.encrypt_in_place(&key, self.nonce, buf, self.aad);
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

        cal.decrypt_in_place(&key, self.nonce, buf, self.tag, self.aad)
            .unwrap();
        assert_eq!(
            buf, self.plaintext,
            "decryption mismatch: expected {:02x?}, got {:02x?}",
            self.plaintext, buf
        );
    }
}

pub fn test_aead_aesccm_16_64_128(cal: &mut impl embedded_cal::AeadProvider) {
    for case in aes_ccm::AES_CCM_16_64_128 {
        case.test(cal);
    }
}

pub fn test_aead_aesccm_16_64_256(cal: &mut impl embedded_cal::AeadProvider) {
    for case in aes_ccm::AES_CCM_16_64_256 {
        case.test(cal);
    }
}
