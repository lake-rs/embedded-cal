// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
#![no_std]
//! Examples that run some cryptographic operations.
//!
//! This is not rigorous testing, but a collection of functions that serve both as a quick "how to
//! use" example and as a quick sanity check.

use embedded_cal::accessor::*;
use embedded_cal::*;

use defmt_or_log::wrappers::Hex;
use defmt_or_log::*;

/// Shows a brief note on which implementations is being used, and then runs all other `show_*`
/// functions in this module.
pub fn show_examples(cal: &mut impl embedded_cal::Cal) {
    info!(
        "Running examples on a Cal of type {}",
        core::any::type_name_of_val(&cal)
    );

    show_sha256_example(cal);

    show_ecdh_example(cal);

    show_aead_tests(cal);
}

/// Hashes a "hello world" string with the SHA-256 hash, if available.
pub fn show_sha256_example(cal: &mut impl embedded_cal::Cal) {
    let sha256 = HashAlgorithm::from_ni_name("sha-256");
    if let Some(sha256) = sha256 {
        let hash_me = "hello world";
        let hashed = cal.hash().hash(sha256, hash_me.as_bytes());
        info!(
            "Computed SHA-256 hash of {:?} (encoded in ASCII); hash is {}",
            hash_me,
            Hex(hashed.as_ref())
        );
    } else {
        warn!("Skipping hash demo: Suite does not support SHA-256");
    }
}

/// Selects a key from a list of a peer's identity keys (based on the Cal's supported curves), and
/// runs static-ephemeral Diffie-Hellman on it.
// See https://github.com/lake-rs/embedded-cal/issues/131 on why this needs a full generic rather
// than just an impl.
pub fn show_ecdh_example<C: embedded_cal::Cal>(cal: &mut C) {
    info!("Looking to find a matching ECDH curve for Diffie-Hellman key establishment based on a set of public key options.");
    // In an actual protocol, these could be public static keys offered by the peer.
    let peer_keys = [
        (1, &b"the p256 key offered by the peer"[..]),
        (4, &b"if anyone finds pivkey were lost"[..]),
        (
            5,
            &b"because these are obviously not pubkeys from real secrts"[..],
        ),
    ];

    for (crvnum, peer_pub) in peer_keys.iter().rev() {
        let Some(crv): Option<DhAlgorithmOf<C>> = DhAlgorithm::from_cose_ecdh(*crvnum) else {
            continue;
        };
        info!("Agreeing to use curve {}", crvnum);

        let Ok(peer_pub) = cal.dh().import_publickey_bytes(crv.clone(), peer_pub) else {
            error!("Peer's public key failed to load");
            return;
        };
        let private = cal.dh().generate(crv);
        let our_pub = cal.dh().public_key(&private);
        let our_pub = cal.dh().export_publickey_bytes(&our_pub);
        info!("Public part of our ephemeral key is {}", Hex(our_pub));
        let secret = cal
            .dh()
            .shared_secret(&private, &peer_pub)
            .expect("Curves match by construction");
        let secret = cal.dh().raw_secret_bytes(&secret);
        info!("Shared secret with that peer is {}", Hex(secret));

        return;
    }

    warn!("No matching ECDH algorithm found.");
}

/// Runs through AEAD test vectors for some known algorithms
pub fn show_aead_tests<C: embedded_cal::Cal>(cal: &mut C) {
    let aead_algs = [
        (
            1,
            embedded_cal_testvectors::aead::aes_gcm::test_128 as fn(&mut C),
        ),
        (
            3,
            embedded_cal_testvectors::aead::aes_gcm::test_256 as fn(&mut C),
        ),
        (
            10,
            embedded_cal_testvectors::aead::aes_ccm::test_16_64_128 as fn(&mut C),
        ),
        (
            11,
            embedded_cal_testvectors::aead::aes_ccm::test_16_64_256 as fn(&mut C),
        ),
    ];
    let mut any = false;
    for (algnum, fun) in aead_algs {
        let Some(alg): Option<AeadAlgorithmOf<C>> = AeadAlgorithm::from_cose_number(algnum) else {
            continue;
        };
        any = true;

        info!(
            "Running AEAD test vectors of COSE algorithm {} ({:?})",
            algnum,
            Debug2Format(&alg)
        );
        fun(cal);
    }
    if any {
        info!("All AEAD tests passed.");
    } else {
        warn!("No AEAD algorithms for which tests cases are known are supproted by the cal.");
    }
}
