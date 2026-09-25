// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every vector RFC 8439 publishes for ChaCha20, transcribed from the text.
//!
//! Appendix A.1 is the block function at five different counters and keys, A.2
//! is three encryptions, and A.4 is the one-time key an AEAD takes out of the
//! first thirty-two bytes of a keystream. All three are the same call here:
//! what changes is how much of the keystream is asked for and what it is laid
//! over.
//!
//! A.5 is not here. It is the AEAD with a twelve-byte nonce, which this crate
//! does not build — what does is one crate up, and it builds the other one.
//!
//! The hexadecimal is contiguous and the lengths are asserted before anything
//! is compared, because a vector transcribed one byte short fails in a way that
//! reads like an implementation bug.

use std::vec;
use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_core::consts::chacha::{BLOCK_SIZE, KEY_SIZE, NONCE_SIZE};
use redoubt_asm::Backend;

use crate::chacha20::ChaCha20;

use super::support::vectors::hex;

/// Hexadecimal of a length the document decides rather than the type.
fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "a transcribed vector is whole bytes");

    (0..value.len() / 2)
        .map(|at| {
            u8::from_str_radix(&value[at * 2..at * 2 + 2], 16)
                .expect("a transcribed vector is hexadecimal")
        })
        .collect()
}

/// One keystream block, as A.1 publishes it.
struct Block {
    from: &'static str,
    key: &'static str,
    nonce: &'static str,
    counter: u32,
    keystream: &'static str,
}

/// RFC 8439 A.1, all five.
const BLOCKS: &[Block] = &[
    Block {
        from: "A.1 #1",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 0,
        keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                    da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    },
    Block {
        from: "A.1 #2",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 1,
        keystream: "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
                    29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    },
    Block {
        from: "A.1 #3",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000000",
        counter: 1,
        keystream: "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
                    8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
    },
    Block {
        from: "A.1 #4",
        key: "00ff000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 2,
        keystream: "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
                    13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
    },
    Block {
        from: "A.1 #5",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000002",
        counter: 0,
        keystream: "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
                    8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
    },
];

/// One encryption, as A.2 publishes it.
struct Encryption {
    from: &'static str,
    key: &'static str,
    nonce: &'static str,
    counter: u32,
    plaintext: &'static str,
    ciphertext: &'static str,
}

/// RFC 8439 A.2, all three. The third is the longest the document prints.
///
/// The hexadecimal is on one line each however long it gets. Wrapped by hand it
/// was wrong twice, and the odd-length assertion above is what said so.
#[rustfmt::skip]
const ENCRYPTIONS: &[Encryption] = &[
    Encryption {
        from: "A.2 #1",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 0,
        plaintext: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ciphertext: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    },
    Encryption {
        from: "A.2 #2",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000002",
        counter: 1,
        plaintext: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        ciphertext: "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
    },
    Encryption {
        from: "A.2 #3",
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000000000000000002",
        counter: 42,
        plaintext: "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        ciphertext: "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
    },
];

/// The one-time key A.4 takes out of a keystream.
struct OneTimeKey {
    from: &'static str,
    key: &'static str,
    nonce: &'static str,
    one_time_key: &'static str,
}

/// RFC 8439 A.4, all three.
///
/// The counter is zero in every one: that is what the derivation is.
const ONE_TIME_KEYS: &[OneTimeKey] = &[
    OneTimeKey {
        from: "A.4 #1",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        one_time_key: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    },
    OneTimeKey {
        from: "A.4 #2",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000002",
        one_time_key: "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
    },
    OneTimeKey {
        from: "A.4 #3",
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000000000000000002",
        one_time_key: "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
    },
];

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_keystream_block(#[case] backend: Backend) {
    let chacha = ChaCha20::new();

    for one in BLOCKS {
        let expected = bytes(one.keystream);

        assert_eq!(
            expected.len(),
            BLOCK_SIZE,
            "{}: the keystream transcribed is not a block",
            one.from
        );

        // A keystream is what a block of zeros comes back as.
        let mut data = vec![0u8; BLOCK_SIZE];

        chacha.xor(
            backend,
            &hex::<KEY_SIZE>(one.key),
            &hex::<NONCE_SIZE>(one.nonce),
            one.counter,
            &mut data,
        );

        assert_eq!(data, expected, "RFC 8439 {}", one.from);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_ciphertexts(#[case] backend: Backend) {
    let chacha = ChaCha20::new();

    for one in ENCRYPTIONS {
        let mut data = bytes(one.plaintext);
        let expected = bytes(one.ciphertext);

        assert_eq!(
            data.len(),
            expected.len(),
            "{}: the two sides transcribed are different lengths",
            one.from
        );

        chacha.xor(
            backend,
            &hex::<KEY_SIZE>(one.key),
            &hex::<NONCE_SIZE>(one.nonce),
            one.counter,
            &mut data,
        );

        assert_eq!(data, expected, "RFC 8439 {}", one.from);
    }
}

/// The derivation an AEAD makes its authenticator's key with.
///
/// Thirty-two bytes of the keystream at counter zero, which is what the crate
/// above asks for before it starts the message at counter one.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_one_time_key(#[case] backend: Backend) {
    let chacha = ChaCha20::new();

    for one in ONE_TIME_KEYS {
        let expected = bytes(one.one_time_key);

        assert_eq!(
            expected.len(),
            KEY_SIZE,
            "{}: the one-time key transcribed is not a key",
            one.from
        );

        let mut data = vec![0u8; KEY_SIZE];

        chacha.xor(
            backend,
            &hex::<KEY_SIZE>(one.key),
            &hex::<NONCE_SIZE>(one.nonce),
            0,
            &mut data,
        );

        assert_eq!(data, expected, "RFC 8439 {}", one.from);
    }
}
