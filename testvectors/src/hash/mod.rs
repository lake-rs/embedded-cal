// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

pub mod sha2;
pub mod sha3;

pub fn test_hash_algorithm<Cal: embedded_cal::HashProvider, const DIGEST_SIZE: usize>(
    cal: &mut Cal,
    hash_algorithm: Cal::Algorithm,
    test_vectors: &[(&[u8], [u8; DIGEST_SIZE])],
) {
    for (tv_data, tv_result) in test_vectors {
        assert_eq!(
            cal.hash(hash_algorithm.clone(), tv_data).as_ref(),
            tv_result,
            "Hash values mismatch"
        );

        let mut hash = cal.init(hash_algorithm.clone());
        let mid = tv_data.len() / 2;
        let postmid = mid + 1;
        if tv_data.len() < postmid {
            continue;
        }
        cal.update(&mut hash, &tv_data[..mid]);
        cal.update(&mut hash, &tv_data[mid..postmid]);
        cal.update(&mut hash, &tv_data[postmid..]);
        assert_eq!(
            &cal.finalize(hash).as_ref(),
            tv_result,
            "Hash values mismatch when input is fed in chunks"
        );
    }
}
