// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The published answers, transcribed.
//!
//! RFC 8439 §2.4.2 and A.2 for ChaCha20, §2.3.2 and A.1 for the block function
//! and the state after the rounds, and draft-irtf-cfrg-xchacha §2.2.1 and A.2
//! for HChaCha20 and XChaCha20.

use redoubt_aead_v2_core::consts::chacha::{KEY_SIZE, NONCE_SIZE};

/// Hexadecimal published as contiguous lines, decoded only in tests.
pub(crate) fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    core::array::from_fn(|at| {
        u8::from_str_radix(&value[at * 2..at * 2 + 2], 16)
            .expect("a transcribed vector is hexadecimal")
    })
}

/// RFC 8439 §2.3.2, before the twenty rounds.
pub(crate) const INITIAL: [u32; 16] = [
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000, 0x4a000000, 0x00000000,
];

/// RFC 8439 §2.3.2, after the rounds and before feed-forward.
pub(crate) const PERMUTED: [u32; 16] = [
    0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
    0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
];

/// RFC 8439 §2.3.2, the serialized block after feed-forward.
pub(crate) const BLOCK: &str = concat!(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
);

/// RFC 8439 A.1 vector #1: zero key, zero nonce and counter zero.
pub(crate) const ZERO_BLOCK: &str = concat!(
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
);

/// draft-irtf-cfrg-xchacha-03 §2.2.1.
pub(crate) const HNONCE: &str = "000000090000004a0000000031415927";
pub(crate) const SUBKEY: &str = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";

/// draft-irtf-cfrg-xchacha-03 A.3.2. The last nonce byte is 58, not 57.
pub(crate) const XKEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
pub(crate) const XNONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555658";
pub(crate) const DHOLE: &[u8] =
    b"The dhole (pronounced \"dole\") is also known as the Asiatic wild \
dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like \
a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, \
jackals, and foxes in the taxonomic family Canidae.";

/// A.3.2.1 and A.3.2.2, ciphertext at counters zero and one.
pub(crate) const XCIPHERTEXT: [&str; 2] = [
    concat!(
        "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9",
        "8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d",
        "4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da",
        "ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744",
        "3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240",
        "7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c",
        "09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae",
        "577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c",
        "cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663",
        "93b93111c1a55dd7421a10184974c7c5",
    ),
    concat!(
        "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87",
        "ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05",
        "3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f",
        "7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201",
        "12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc",
        "047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63",
        "d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73",
        "c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4",
        "d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683",
        "8a9c71f70b5b5907a66f7ea49aadc409",
    ),
];

/// One encryption somebody else published.
pub(crate) struct Vector {
    /// Where it comes from, so a failure can be read against the document.
    pub(crate) from: &'static str,
    /// The key.
    pub(crate) key: [u8; KEY_SIZE],
    /// The nonce.
    pub(crate) nonce: [u8; NONCE_SIZE],
    /// Where the keystream starts.
    pub(crate) counter: u32,
    /// What goes in.
    pub(crate) plaintext: &'static [u8],
    /// What comes out.
    pub(crate) ciphertext: &'static [u8],
}

/// RFC 8439 §2.4.2, the one that spans more than a block and less than three.
pub(crate) const SUNSCREEN: Vector = Vector {
    from: "RFC 8439 §2.4.2",
    key: [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ],
    nonce: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ],
    counter: 1,
    plaintext: b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
tip for the future, sunscreen would be it.",
    ciphertext: &[
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
        0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
        0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e,
        0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
        0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4,
        0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
    ],
};

/// Every ChaCha20 encryption transcribed so far.
pub(crate) const VECTORS: &[Vector] = &[SUNSCREEN];
