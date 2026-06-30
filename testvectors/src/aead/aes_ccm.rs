// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
use hexlit::hex;

use crate::aead::AeadCase;

pub const AES_CCM_16_64_128: &[AeadCase] = &[
    // From Appendix C.4 of RFC8613
    AeadCase {
        alg_cose: 10,
        key: &hex!("f0910ed7295e6ad4b54fc793154302ff"),
        nonce: &hex!("4622d4dd6d944168eefb549868"),
        aad: &hex!("8368456e63727970743040488501810a40411440"),
        plaintext: &hex!("01b3747631"),
        ciphertext: &hex!("612f1092f1"),
        tag: &hex!("776f1c1668b3825e"),
    },
    // From RFC3610 (Packet Vector #1)
    AeadCase {
        alg_cose: 10,
        key: &hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        nonce: &hex!("00000003020100a0a1a2a3a4a5"),
        aad: &hex!("0001020304050607"),
        plaintext: &hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e"),
        ciphertext: &hex!("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"),
        tag: &hex!("17e8d12cfdf926e0"),
    },
    // From RFC3610 (Packet Vector #2)
    AeadCase {
        alg_cose: 10,
        key: &hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        nonce: &hex!("00000004030201a0a1a2a3a4a5"),
        aad: &hex!("0001020304050607"),
        plaintext: &hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        ciphertext: &hex!("72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b"),
        tag: &hex!("a091d56e10400916"),
    },
    // From RFC3610 (Packet Vector #3)
    AeadCase {
        alg_cose: 10,
        key: &hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        nonce: &hex!("00000005040302a0a1a2a3a4a5"),
        aad: &hex!("0001020304050607"),
        plaintext: &hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        ciphertext: &hex!("51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da859657"),
        tag: &hex!("4adaa76fbd9fb0c5"),
    },
    // From RFC3610 (Packet Vector #4)
    AeadCase {
        alg_cose: 10,
        key: &hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        nonce: &hex!("00000006050403a0a1a2a3a4a5"),
        aad: &hex!("000102030405060708090a0b"),
        plaintext: &hex!("0c0d0e0f101112131415161718191a1b1c1d1e"),
        ciphertext: &hex!("a28c6865939a9a79faaa5c4c2a9d4a91cdac8c"),
        tag: &hex!("96c861b9c9e61ef1"),
    },
    // From RFC3610 (Packet Vector #5)
    AeadCase {
        alg_cose: 10,
        key: &hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        nonce: &hex!("00000007060504a0a1a2a3a4a5"),
        aad: &hex!("000102030405060708090a0b"),
        plaintext: &hex!("0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        ciphertext: &hex!("dcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e"),
        tag: &hex!("51e83f077d9c2d93"),
    },
];

pub const AES_CCM_16_64_256: &[AeadCase] = &[
    // From CCM Test Vector (SP 800-38C)
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("7022eaa52c9da821da72d2edd98f6b91dfe474999b75b34699aeb38465f70c1c"),
        plaintext: &hex!("28ef408d57930086011b167ac04b866e5b58fe6690a0b9c3"),
        ciphertext: &hex!("356367c6cee4453658418d9517f7c6faddcd7c65aef46013"),
        tag: &hex!("8cf050f48c505151"),
    },
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("a61b6c1f0293a7c35520abf158a995e5ae59b43ec5f38ff6fd6529970c9f83ac"),
        plaintext: &hex!("1c5ad37d2a55afbc390b27cde0c42d6651fe191239bfaa27"),
        ciphertext: &hex!("01d6f436b322ea0c6051bc2237786df2d76b9b1107eb73f7"),
        tag: &hex!("6bca352f92f383e1"),
    },
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("0f1c6dffeda98f7a159f9cc61820bfb29910d8eaa41b751a41f9fe5648f02fba"),
        plaintext: &hex!("6efe6652d46a84166d30befe2fbee0795e9475b401eedd60"),
        ciphertext: &hex!("737241194d1dc1a6346a2511f802a0edd801f7b73fba04b0"),
        tag: &hex!("14fd7c84052208d9"),
    },
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("151110a9ce7e44e5d76d9cad53c1819317527fcd169051f01c6a3efcc06ea999"),
        plaintext: &hex!("55b791ee495299916ff3c2327b4990952bebd0a2da9acfc5"),
        ciphertext: &hex!("483bb6a5d025dc2136a959ddacf5d001ad7e52a1e4ce1615"),
        tag: &hex!("c3ebc7214b9eef31"),
    },
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("0ba1210696d735eebc13b609d0ec33bc740805105dd82f065b82892b931f1e6d"),
        plaintext: &hex!("794a86f5b20d344ad86fd5523d08f1864737be57731440c2"),
        ciphertext: &hex!("64c6a1be2b7a71fa81354ebdeab4b112c1a23c544d409912"),
        tag: &hex!("eff08182f8a00f13"),
    },
    AeadCase {
        alg_cose: 11,
        key: &hex!("bae73483de27b581a7c13f178a6d7bda168c1b4a1cb9180512a13e3ab914eb61"),
        nonce: &hex!("daf54faef6e4fc7867624b76f2"),
        aad: &hex!("5a3b71b0fdecce8bd759d3d72321b5c3e882c82627c14e0b59cc8c6d191f243f"),
        plaintext: &hex!("efa6ddd6fb8e4480a0f64414694e5f9e7f2e9b97cbe9cd14"),
        ciphertext: &hex!("f22afa9d62f90130f9acdffbbef21f0af9bb1994f5bd14c4"),
        tag: &hex!("6894be1f8fa14538"),
    },
];
