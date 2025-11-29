// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Poly1305 tests using RFC 8439 Section 2.5.2 test vector.

use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::xchacha20poly1305::poly1305::{Poly1305, Poly1305Block, Poly1305Final};

#[test]
fn test_poly1305_zeroization_on_drop() {
    let mac = Poly1305::default();

    assert!(mac.is_zeroized());
    mac.assert_zeroize_on_drop();
}

#[test]
fn test_poly1305_block_zeroization_on_drop() {
    let block = Poly1305Block::default();

    assert!(block.is_zeroized());
    block.assert_zeroize_on_drop();
}

#[test]
fn test_poly1305_final_zeroization_on_drop() {
    let fin = Poly1305Final::default();

    assert!(fin.is_zeroized());
    fin.assert_zeroize_on_drop();
}

/// RFC 8439 Section 2.5.2 test vector
#[test]
fn test_rfc8439_section_2_5_2() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";

    // RFC 8439 Section 2.5.2 expected tag
    // Tag: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
    let expected: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];

    let mut our_tag = [0u8; 16];
    Poly1305::compute(&key, message, &mut our_tag);

    assert_eq!(our_tag, expected, "Tag doesn't match RFC 8439");
}

/// Test empty message
#[test]
fn test_empty_message() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];

    // Empty message should just return s (the second half of the key)
    let mut tag = [0u8; 16];
    Poly1305::compute(&key, b"", &mut tag);

    // With empty input, tag = s = key[16..32]
    assert_eq!(&tag, &key[16..32]);
}

/// Test single full block (exactly 16 bytes)
#[test]
fn test_single_full_block() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"0123456789abcdef"; // exactly 16 bytes

    let mut tag = [0u8; 16];
    Poly1305::compute(&key, message, &mut tag);

    // Just verify it produces a 16-byte tag without panicking
    assert_eq!(tag.len(), 16);
}
