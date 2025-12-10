#![no_std]
use hexlit::hex;

pub const SHA256HASHES: &[(&[u8], [u8; 32])] = &[
    (
        b"",
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ),
    (
        b"hello world",
        hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
    ),
];

pub fn test_hash_algorithm_sha256<Cal: embedded_cal::HashProvider>(cal: &mut Cal) {
    // Equivalence with other constructors can be handled via
    // embedded_cal::test_hash_algorithm_sha256 (or should we move this in here?)

    // If this test is run on a concrete type, we expect it to provide the algorithm.
    let sha256 = Cal::Algorithm::from_ni_id(1).unwrap();

    use embedded_cal::HashAlgorithm;

    for (tv_data, tv_result) in SHA256HASHES {
        assert_eq!(
            cal.hash(sha256.clone(), tv_data).as_ref(),
            tv_result,
            "Hash values mismatch"
        );

        let mut hash = cal.init(sha256.clone());
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
