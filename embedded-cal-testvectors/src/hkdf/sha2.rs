// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use hexlit::hex;

/// HKDF-SHA-256 test cases from RFC 5869 Appendix A.
///
/// Each entry is `(salt, ikm, info, expected_prk, expected_okm)`.
/// `salt` is `None` for test case 3 (no salt provided).
type HkdfCase = (
    Option<&'static [u8]>,
    &'static [u8],
    &'static [u8],
    [u8; 32],
    &'static [u8],
);
pub const HKDF_SHA256: &[HkdfCase] = &[
    // Test Case 1
    (
        Some(&hex!("000102030405060708090a0b0c")),
        &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &hex!("f0f1f2f3f4f5f6f7f8f9"),
        hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        &hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ),
    ),
    // Test Case 2
    (
        Some(&hex!(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )),
        &hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ),
        &hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ),
        hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
        &hex!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ),
    ),
    // Test Case 3 — no salt, empty info
    (
        None,
        &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        b"",
        hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
        &hex!(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        ),
    ),
];

pub fn test_hkdf_sha256<Cal>(cal: &mut Cal)
where
    Cal: embedded_cal::HkdfProvider,
{
    use embedded_cal::HmacAlgorithm;
    let alg = <Cal as embedded_cal::HmacProvider>::Algorithm::from_cose_number(5i8)
        .expect("HkdfProvider must recognize COSE 5 (HMAC-SHA-256)");

    for (salt, ikm, info, expected_prk, expected_okm) in HKDF_SHA256 {
        let prk = cal
            .hkdf_extract(alg.clone(), *salt, ikm)
            .expect("HKDF-Extract failed");
        assert_eq!(
            prk.as_ref(),
            expected_prk.as_ref(),
            "HKDF-Extract PRK mismatch"
        );

        let mut okm = [0u8; 82]; // large enough for test case 2 (82 bytes)
        let okm = &mut okm[..expected_okm.len()];
        cal.hkdf_expand(alg.clone(), prk.as_ref(), info, okm)
            .expect("HKDF-Expand failed");
        assert_eq!(okm, *expected_okm, "HKDF-Expand OKM mismatch");
        // Also test the combined hkdf() method using test case 1 only (salt is Some).
        if salt.is_some() {
            let mut okm2 = [0u8; 82];
            let okm2 = &mut okm2[..expected_okm.len()];
            cal.hkdf(alg.clone(), *salt, ikm, info, okm2)
                .expect("hkdf() combined call failed");
            assert_eq!(okm2, *expected_okm, "hkdf() combined call OKM mismatch");
        }
    }
}
