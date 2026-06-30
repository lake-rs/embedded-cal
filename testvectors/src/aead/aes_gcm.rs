// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Wycheproof Authors
//! Test vectors are a subset of Wychpreoof vectors.
//!
//! Source: <https://github.com/C2SP/wycheproof/blob/ee7b4f7e611928cbe163dc6f5e54527bfd166f34/testvectors_v1/aes_gcm_test.json>
use hexlit::hex;

use crate::aead::AeadCase;

pub const AES_GCM_128: &[AeadCase] = &[
    // tcId: 1
    AeadCase {
        alg_cose: 1,
        key: &hex!("5b9604fe14eadba931b0ccf34843dab9"),
        nonce: &hex!("028318abc1824029138141a2"),
        aad: &[],
        plaintext: &hex!("001d0c231287c1182784554ca3a21908"),
        ciphertext: &hex!("26073cc1d851beff176384dc9896d5ff"),
        tag: &hex!("0a3ea7a5487cb5f7d70fb6c58d038554"),
    },
    // tcId: 2
    AeadCase {
        alg_cose: 1,
        key: &hex!("5b9604fe14eadba931b0ccf34843dab9"),
        nonce: &hex!("921d2507fa8007b7bd067d34"),
        aad: &hex!("00112233445566778899aabbccddeeff"),
        plaintext: &hex!("001d0c231287c1182784554ca3a21908"),
        ciphertext: &hex!("49d8b9783e911913d87094d1f63cc765"),
        tag: &hex!("1e348ba07cca2cf04c618cb4d43a5b92"),
    },
    // tcId: 4
    AeadCase {
        alg_cose: 1,
        key: &hex!("bedcfb5a011ebc84600fcb296c15af0d"),
        nonce: &hex!("438a547a94ea88dce46c6c85"),
        aad: &[],
        plaintext: &[],
        ciphertext: &[],
        tag: &hex!("960247ba5cde02e41a313c4c0136edc3"),
    },
    // tcId: 5
    AeadCase {
        alg_cose: 1,
        key: &hex!("384ea416ac3c2f51a76e7d8226346d4e"),
        nonce: &hex!("b30c084727ad1c592ac21d12"),
        aad: &[],
        plaintext: &hex!("35"),
        ciphertext: &hex!("54"),
        tag: &hex!("7c1e4ae88bb27e5638343cb9fd3f6337"),
    },
    // tcId: 15
    AeadCase {
        alg_cose: 1,
        key: &hex!("bb571c160132b0c8d5d190d0bc356ddc"),
        nonce: &hex!("2596c440cf0232950ec66bc4"),
        aad: &[],
        plaintext: &hex!(
            "053be1b6190a717fc74c879e6fd62dc44628495507e50d662271dee795a4ad26e0c4f86cb6b20ac6bd9d682d2d8a05c9dad875a6911b49ea0af4f17c97a5f2"
        ),
        ciphertext: &hex!(
            "b1cfad142a462f3656e0921627fd41d4f1fa8e2f8bd94bb51fdcf06f606296f7d2885337bed7a4ca6ddb4a9fc7fdb2476b5f7fa5220e1d6752a5e7c31c916c"
        ),
        tag: &hex!("a231b617352ffdb63d32d69d99e7d629"),
    },
    // tcId: 24
    AeadCase {
        alg_cose: 1,
        key: &hex!("4a30eac07b788b7354a90e6448f56676"),
        nonce: &hex!("c359d567616b6384ac20a43f"),
        aad: &[],
        plaintext: &hex!(
            "9a17b9d1dbe666f7431cbdd3b3173948c7ac13f268e12807256d2e5831ae67a14116144910b38368934571daff9d4004ba959b3cae2669e6eed49e750ca228415c6f7d1c1f2d3dbb02f4dfa49483a7f80fbcc1cb01d22c67817cc7a2bd2714eb62cdf8fb884a66ed245167cdb22e0dbc7b153e648714dfe83414696cffa892daf5af8820d562bdf55f76be5584a34b7e349d10d76c6e68305835b551a41ebf48e068320d875334a6a2d3108b1e93f7aa8da485d7a5470d805e0dd38c09feaa0f494d0572de314a287439f48aee5a2fa8e9850c6127ee88d50c5e8a2ac3eaa7b2fdd1589813fb3affa6589831df132bd576fbed21717e2b6766e593ed74dab35da125c433763ea90234dc6f01d37be14c78b8861be1fb4c8296b3faee65b6ef8a9daa6884e936359346f2da9f6981f9d64f676767641ada628aa8c7129326bd4ee57e515a2f78ba18c595b9bc1d0f49068734a67e635554eee688816061e904a4e05125d0e7797305451a7c3a1a3c507daedb990c12ca290a0f554aa8e834653aa21a0469d3b0c08ee512b323cb193779c9fe2f2b3f03794cd42f0220031d0c8eeb9c73a3283a599bc78da3b5b41b243edf082b23801a15d9956fca60f35acfb65c4d06d28aff81a1ca98c6faf8645be920bd87c03c054a0469b292ae34d05860e8d9b061300370463dcd5fcd6fb1d6b1acc9b4eb25cabd9de4e61d44922fcc"
        ),
        ciphertext: &hex!(
            "3e13588d5a014dcc1cbf46bd6c3f06dfbef1464649e79a9bcbd99484686d72653827882dba803a5683f82a9bdfec6b44b29b7c13f3f2b5dbc675780540f6a8a08e45f59fa88021095f8b3db5f10bc21721a56d65a589216cbc5b1915cbe7e2f8612a9d24b30ecde2a296a96f48ad1160720537312208e9b6824e6413f2084f229dc6e953c4b8a054e3c368ef1f70dd9cf276caa4cc251e475f507a2bd072b7f4a1311302f617e2cc594eb6a0c49ac173db07831945f5129a38e45135beb97b39393f73d0977e324820533f3dd752051996543a0620ebba50288923f1d0181badb2204c7469e8b4b5d14a984c3f0f3d34bb383416149e0a0ca14f4f6dfe58902a48ecd3bdbc02a8c84bb303e83491824b2ca976991b229d715af2bf4ba3385d7d93e3ada52f12317b73e2939628d7589810d6a278d4c24e907b4ffce0d177b040e9dce97b63c9b8c1743ad6febd0c9a273f648b91ba5b5719159785db770c664290e93d69ba14757d8bba68f0f93a136031a97c72f2be6bf9e15237e998395930b4d1f87b57a5fa65494dc8feb761bdaffed4b3bf0073e9244abb4a3a7e15e2d52a3bb8446766f0e7563702a943dd16d5db9dbecb0044e462bed17eab81b312aa4f32415db8f09bc0cc2db7406f4f67862af986b965237913d119ca85b8d64b4e610034891f78433f370fbe6c9996a69d0de308ed685f4339f9b67fa5ec100e"
        ),
        tag: &hex!("58743a6d49272df201d81dcccdaf76fa"),
    },
    // tcId: 28
    AeadCase {
        alg_cose: 1,
        key: &hex!("c4b03435b91fc52e09eff27e4dc3fb42"),
        nonce: &hex!("5046e7e08f0747e1efccb09e"),
        aad: &hex!(
            "75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb1695a5e5a6317b83690ba0538fb11e325ca"
        ),
        plaintext: &hex!("8e887b224e8b89c82e9a641cf579e6879e1111c7"),
        ciphertext: &hex!("b6786812574a254eb43b1cb1d1753564c6b520e9"),
        tag: &hex!("ad8c09610d508f3d0f03cc523c0d5fcc"),
    },
    // tcId: 33
    AeadCase {
        alg_cose: 1,
        key: &hex!("bf2056baaf45c5a00a733b49f10b7dd0"),
        nonce: &hex!("fef1b243b44ba92b47c6626b"),
        aad: &hex!(
            "1bb3a17907279ebff63593de97a64e5ceaf9e1d407e5a5eec1ce0f62586f0dfddb7a3a83fd164e800bcbc6fb089d6a247dfa444633f4663ae1e0bdf37b50a7a01f506e2220bbdd4b08c59fe60e455bdaeda7e5a0cdb2e6dfca66381a72962fa8a6f9847a87135ccf02a40da5b3b8e91e6e1f31542f85f90bce1de05188fe57355329031c66b3fde18bbdcbd2cbec42ea1d0fc803abed2f15c41d2f122674ea91b7280e818acb7549fe63135d2109b4014ec6002745301bd0ac59ca8e4f8d2fb699347b74e17818e3a57fa69c759312dcfde155b2a558a2385c8adab8a6d57f0f497eaf0833e3d930e83fed88c91e18a74c4f5ff45925a2bbdda22f9a4f1196"
        ),
        plaintext: &hex!("7e8c2d8a65f539210c047422ae57549195a08393"),
        ciphertext: &hex!("1fcc05bf4960fd02475c072f9eee8150994edcb9"),
        tag: &hex!("f3e092f2415f7f0ce88f37a2495dce48"),
    },
    // tcId: 39
    AeadCase {
        alg_cose: 1,
        key: &hex!("00112233445566778899aabbccddeeff"),
        nonce: &hex!("000000000000000000000000"),
        aad: &[],
        plaintext: &hex!("ebd4a3e10cf6d41c50aeae007563b072"),
        ciphertext: &hex!("f62d84d649e56bc8cfedc5d74a51e2f7"),
        tag: &hex!("ffffffffffffffffffffffffffffffff"),
    },
    // tcId: 40
    AeadCase {
        alg_cose: 1,
        key: &hex!("00112233445566778899aabbccddeeff"),
        nonce: &hex!("ffffffffffffffffffffffff"),
        aad: &[],
        plaintext: &hex!("d593c4d8224f1b100c35e4f6c4006543"),
        ciphertext: &hex!("431f31e6840931fd95f94bf88296ff69"),
        tag: &hex!("00000000000000000000000000000000"),
    },
];

pub const AES_GCM_256: &[AeadCase] = &[
    // tcId: 91
    AeadCase {
        alg_cose: 3,
        key: &hex!("92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20"),
        nonce: &hex!("00112233445566778899aabb"),
        aad: &hex!("00000000ffffffff"),
        plaintext: &hex!("00010203040506070809"),
        ciphertext: &hex!("e27abdd2d2a53d2f136b"),
        tag: &hex!("9a4a2579529301bcfb71c78d4060f52c"),
    },
    // tcId: 92
    AeadCase {
        alg_cose: 3,
        key: &hex!("29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123"),
        nonce: &hex!("00112233445566778899aabb"),
        aad: &hex!("aabbccddeeff"),
        plaintext: &[],
        ciphertext: &[],
        tag: &hex!("2a7d77fa526b8250cb296078926b5020"),
    },
    // tcId: 93
    AeadCase {
        alg_cose: 3,
        key: &hex!("80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0"),
        nonce: &hex!("4da5bf8dfd5852c1ea12379d"),
        aad: &[],
        plaintext: &[],
        ciphertext: &[],
        tag: &hex!("4771a7c404a472966cea8f73c8bfe17a"),
    },
    // tcId: 94
    AeadCase {
        alg_cose: 3,
        key: &hex!("cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273"),
        nonce: &hex!("99e23ec48985bccdeeab60f1"),
        aad: &[],
        plaintext: &hex!("2a"),
        ciphertext: &hex!("06"),
        tag: &hex!("633c1e9703ef744ffffb40edf9d14355"),
    },
    // tcId: 101
    AeadCase {
        alg_cose: 3,
        key: &hex!("cdccfe3f46d782ef47df4e72f0c02d9c7f774def970d23486f11a57f54247f17"),
        nonce: &hex!("376187894605a8d45e30de51"),
        aad: &hex!("956846a209e087ed"),
        plaintext: &hex!("e28e0e9f9d22463ac0e42639b530f42102fded75"),
        ciphertext: &hex!("feca44952447015b5df1f456df8ca4bb4eee2ce2"),
        tag: &hex!("082e91924deeb77880e1b1c84f9b8d30"),
    },
    // tcId: 109
    AeadCase {
        alg_cose: 3,
        key: &hex!("7f7c5804a680f61924966725dba2a80d85267c2e03c7c234b045b24ec8e23528"),
        nonce: &hex!("2d9bf8b636f337d265b0904c"),
        aad: &[],
        plaintext: &hex!(
            "e2f85fb176840c38345da0f0f8db6cdbc45a123165f244ff5389fe65bf341fa131130751b5c739a9931d5a57b141dc7b5b0c5a2ca07331c2dc04b2657b0289878dea0ef7d5601465b78a65795f0f3181304e58a261feb1d394f3c33cabae189941755d7654bb7bef08c31bd2c5ce1203eebc015ae040da2a851c2ba3c62e699356"
        ),
        ciphertext: &hex!(
            "d7380d10b22c3ae584531e9e4ee73d387f69dbbb3d3d9fdb4971ed2750b31913f79e4c00cf1b76933bbb75d39d8a6429a2528e9bd60e65fa6ffff9e01a8758e7b58409fa3f370cc32a63aa60a54c36d733e8f6dfccd5c3120d05c6e33140c00562865532b2c689de98769d3386e7a3ae679e404e062536ca046261211a426fb586"
        ),
        tag: &hex!("753f6c57c0cc2a075e68d082f6e83590"),
    },
    // tcId: 113
    AeadCase {
        alg_cose: 3,
        key: &hex!("4f62e56f7b15035f427849714beb97e6acf88371e1f69b388129bb447273d6b8"),
        nonce: &hex!("137d5c98a92f6dcee4f29d7c"),
        aad: &[],
        plaintext: &hex!(
            "a147b716b86ac8dac7447d5ba60ee8a4191d2c64a3aa04276aee7bf7dc824962c09ace20a7e614cc9e177b5b11819b8f17008a9408e8cd8bb34b401be35368f492c17629b6467299bfd2ec4d9a7f17dea6f9ca084e871fb7fc78c2bf299b810522062726c5cae14b839722ecff499a2b3f082b6d1bfedb752f84a4e77459c9268d63199315363e9aaa39bea7fbbcc60a5eedc8a1a982ad6fa67c295b932eb3999047e0a99b3823032b6b3b7c4c553970afca50cb4e5ce859c25c598eb682005f17aec5526e26493208483679a23ccef6f7403a3f3055affd531a1cb7d183892dd577d526e8da8aa8b8b980a36e176b8d9293e785ac01bdd4dac8cf8dbdd82926f1e31408284fb3aa01f4414ac7aa7832d2ec02dd2db9b6b4b61d8c1cbb31dac7b6afa8d08b6877e439600c4a6fc07511877df2e9ce3a9538a726002a46c083d98124b185730f3b2aea2a01cb626be809f87b2ac100511c5b8fa0e9d40c9c999ea0aa87aad08cfb62c1ba869178be986156f7622d8c48ad80a552e9d08c36671ae232efefc8619c562e715f04ae52db2ad8e4a09e8c671b12289558117f9562d51beb59e29b10dd9eb232e8fcdb1cfdd14899acd693de14a7c076a4656386e23b06415b2c7a93b166cad1048bc605a49a79df3c03a3380de68a4f013e05e5283745d4078ebe308dc8881ced62ed571a93c69e8aae6e51f5e61e4ff75699aa32"
        ),
        ciphertext: &hex!(
            "b194e6c8f83e09515d4ea95c00578fdaee8f9d35ad09a560ba81a51accc49416598516c747e16dbc5c44bfd5c790ba59b47a6f573a43b26cdbb240230b1dca00447770c4cf647df2a79eca3f4a8b2de08f9fbc4489c30f6bcfcd096f1aa4177fa281248e8e19e2ea7d1f049b7053947a3a67e946ebbed67466e009b63debceba54cc881e55e2d68f3f584380d6fb7b0e9a3fdbd709adac3a47d6f9a5fcaf03218e18cca5a7a0e340a774cd5c39d7031b63b5b5b896e1e705b4ded099c3c11150738b2107f61f1423fb72ed0a16070cd6f8a18ae90b167b707c23ddc85a1b6ff5a3ec5e654b1446c6eae787c31a94bc9ab5376dfea31bf8dfbdabce45c750111946e64c22d23c46d7ef644ca02c69205d59b1815a6a6e8b14fe7e2d8ad17fc75e656706b67f257523d517d9f8b83150a88359e56d6432859f8f90eaba70cf90f86995afc85c33992591536ba353ae14a6932dc96ad72687ac34c2d4d5c92e51da246f557785df1944d2c3c83536739b7d8475ba39c639df4ce69859c6ffb9e994545699a3a19d53979bfa34fdec856a9f12ac70bdeacf172721496d76d8073a76e8160d99f4b7466e05a8f006cb448d2af7ee308ca19440aaca08f34422da830e476269c829a2b5b64acea4f1143d1857cc2699ea3bf2e076b16e50a9071cf15352189edf278984102ebcc751d46510b816afafdb3fea37a7d49662ff090392"
        ),
        tag: &hex!("79e64c4c0e8bb3a214955584d2bc8b16"),
    },
    // tcId: 124
    AeadCase {
        alg_cose: 3,
        key: &hex!("e40003d6e08ab80b4bfc8400ef112945a901ec64a1b6536ca92665090d608bc4"),
        nonce: &hex!("9f095dafe6f6e0fbafbbe02e"),
        aad: &hex!(
            "422d5efcffe364905984533f0a579d80b18bda7b29e6e46498effba53c350112c0bbb8dc4ce03bb0c69e1d0baa19f0637108aa4a16b09a281f232839d87b6d0e42be1baa7c67f1be970ea169d3960b9fe0a61f11cd2eb7398c19e641feb43f778e257a397063db5b3a6707e9db62387054f9f9d44f143583e63edad45a00251e5173d7505f22a8bce232e56c2c276a58033ae30d5dbf4e35a862e42af573be38c6406d9b4c7acbf275fe36c0ecf2c4642898a30e6146fac992a16405f98312126b7a3722f5dfb7dd4e4911c1426b2e01d04e9be6db3771100f7d7d4282e4ea585f3646241e807ca64f06a7fa9b7003d710b801d66f517d2d5ebd740872deba13d0"
        ),
        plaintext: &hex!("38c3f44bc5765de1f3d1c3684cd09cddefaf298d"),
        ciphertext: &hex!("d4a79f729487935950ec032e690ab8fe25c4158e"),
        tag: &hex!("876d2f334f47968b10c103859d436db8"),
    },
    // tcId: 128
    AeadCase {
        alg_cose: 3,
        key: &hex!("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"),
        nonce: &hex!("000000000000000000000000"),
        aad: &[],
        plaintext: &hex!("561008fa07a68f5c61285cd013464eaf"),
        ciphertext: &hex!("23293e9b07ca7d1b0cae7cc489a973b3"),
        tag: &hex!("ffffffffffffffffffffffffffffffff"),
    },
    // tcId: 129
    AeadCase {
        alg_cose: 3,
        key: &hex!("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"),
        nonce: &hex!("ffffffffffffffffffffffff"),
        aad: &[],
        plaintext: &hex!("c6152244cea1978d3e0bc274cf8c0b3b"),
        ciphertext: &hex!("7cb6fc7c6abc009efe9551a99f36a421"),
        tag: &hex!("00000000000000000000000000000000"),
    },
];
