// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use hexlit::hex;

/// HMAC-SHA256 test vectors from RFC 4231, test cases 1–4, 6–7.
///
/// Each entry is `(key, data, expected_mac)`.
const HMAC_SHA256: &[(&[u8], &[u8], [u8; 32])] = &[
    // TC1 — short key, short data
    (
        &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        b"Hi There",
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    ),
    // TC2 — ASCII key, ASCII data
    (
        b"Jefe",
        b"what do ya want for nothing?",
        hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ),
    // TC3 — key and data filled with repeated bytes
    (
        &hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        &hex!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    ),
    // TC4 — 25-byte key, 50-byte data
    (
        &hex!("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        &hex!("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    ),
    // TC6 — key longer than block size (131 bytes), exercises key hashing
    (
        &hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    ),
    // TC7 — key longer than block size, data longer than block size
    (
        &hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ),
];

pub fn test_hmac_sha256<Cal: embedded_cal::HmacProvider>(cal: &mut Cal) {
    use embedded_cal::HmacAlgorithm;

    let hmac_sha256 = Cal::Algorithm::from_cose_number(5i8)
        .expect("HmacProvider must recognize COSE 5 (HMAC-SHA-256)");

    for (tv_key, tv_data, tv_mac) in HMAC_SHA256 {
        assert_eq!(
            cal.hmac_with_keydata(hmac_sha256.clone(), tv_key, tv_data)
                .as_ref(),
            tv_mac,
            "HMAC values mismatch"
        );

        let mut state = cal.init_with_keydata(hmac_sha256.clone(), tv_key);
        let mid = tv_data.len() / 2;
        let postmid = mid + 1;
        if tv_data.len() >= postmid {
            cal.update(&mut state, &tv_data[..mid]);
            cal.update(&mut state, &tv_data[mid..postmid]);
            cal.update(&mut state, &tv_data[postmid..]);
        } else {
            cal.update(&mut state, tv_data);
        }
        assert_eq!(
            cal.finalize(state).as_ref(),
            tv_mac,
            "HMAC values mismatch when input is fed in chunks"
        );
    }
}
