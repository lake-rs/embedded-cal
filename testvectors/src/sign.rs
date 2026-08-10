// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use hexlit::hex;

pub struct SignVector {
    cose_alg: i16,
    private_key: &'static [u8],
    public_key: &'static [u8],
    message: &'static [u8],
    r: &'static [u8],
    s: &'static [u8],
}

impl SignVector {
    pub fn test_with<C: embedded_cal::Cal>(&self, cal: &mut C) {
        use embedded_cal::{SignAlgorithm, SignProvider};

        let cal = cal.sign();

        let alg = <C::SignProvider as SignProvider>::Algorithm::from_cose_number(self.cose_alg)
            .expect("algorithm not supported by CAL");

        let private = cal
            .import_secretkey_bytes(alg.clone(), self.private_key)
            .expect("failed to load private key")
            .into();
        let public = cal.public_key(&private);

        assert_eq!(
            cal.export_publickey_bytes(&public).as_ref(),
            self.public_key,
            "public key not derived as expected"
        );

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(self.r);
        sig_bytes[32..].copy_from_slice(self.s);
        let signature = cal
            .import_signature_bytes(alg, &sig_bytes)
            .expect("failed to load known-answer signature");

        cal.verify(&public, self.message, &signature)
            .expect("known-answer signature did not verify");
    }
}

pub const ECDSA_P256: &[SignVector] = &[
    SignVector {
        cose_alg: -7,
        private_key: &hex!("0c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672"),
        public_key: &hex!("439ed13599d6e4f6ce33118b0421d0630e57c6919f6e0a8068c3c85a0c2412bf"),
        message: b"sample",
        r: &hex!("951d683e4af187dc4bf4a91853399fc082c078782ee190032a476cf0ae62bfcd"),
        s: &hex!("fd24f7278499ae4649070ffca0eecbbb745c9162f15cc129ffff6a76f5dd0a58"),
    },
    SignVector {
        cose_alg: -7,
        private_key: &hex!("0519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b18"),
        public_key: &hex!("03f5de2249cd1bd00347244cd6399ac88e514f6267ef2ea44c7fe061cdfd5b76"),
        message: b"This is a longer test message used to exercise multi-block SHA-256 hashing inside the ECDSA test vector generation.",
        r: &hex!("852d93e4833a0f923256beee6d12e6919f741517f8f6b895f1b0d27d70a4d31a"),
        s: &hex!("1b178851c2c51d667b1827e682251a6f4a8391e01012fa103ceb103c46f594a7"),
    },
    SignVector {
        cose_alg: -7,
        private_key: &hex!("7a1e8f2c3b9d4a5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e7"),
        public_key: &hex!("3c976244c661396bf73775d98f90850931a8742d1a4442dfe0ee14fe0c592b8a"),
        message: b"another test vector for embedded-cal ECDSA coverage",
        r: &hex!("23480a65e2b1a5b44db30ee256b83c32ac1db8977fcfcf50d79ca87e7f1bd3e4"),
        s: &hex!("b3e9dfff4d365d454ccc639e844a243a4c3bbc41ad0d1a64f5ac95f5d26acdd7"),
    },
];
