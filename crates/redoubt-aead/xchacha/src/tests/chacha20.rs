// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ChaCha20 unit tests

use redoubt_zero::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::chacha20::{ChaCha20, HChaCha20, XChaCha20};
use crate::consts::{CHACHA20_BERNSTEIN_NONCE_SIZE, CHACHA20_NONCE_SIZE};

// Zeroization tests

#[test]
fn test_chacha20_ietf_zeroization_on_drop() {
    let chacha20: ChaCha20<CHACHA20_NONCE_SIZE> = ChaCha20::default();

    assert!(chacha20.is_zeroized());
    chacha20.assert_zeroize_on_drop();
}

#[test]
fn test_hchacha20_zeroization_on_drop() {
    let hchacha20 = HChaCha20::default();

    assert!(hchacha20.is_zeroized());
    hchacha20.assert_zeroize_on_drop();
}

#[test]
fn test_xchacha20_zeroization_on_drop() {
    let xchacha20 = XChaCha20::default();

    assert!(xchacha20.is_zeroized());
    xchacha20.assert_zeroize_on_drop();
}

// RFC test vectors

/// RFC 8439 Section 2.3.2 - Test Vector for ChaCha20 Block
#[test]
fn test_chacha20_ietf_block() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut state = ChaCha20::<CHACHA20_NONCE_SIZE>::default();
    let mut block = [0u8; 64];
    state.block(&key, &nonce, 1, &mut block);

    // First 16 bytes from RFC 8439 Section 2.3.2
    let expected_first_16: [u8; 16] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4,
    ];
    assert_eq!(&block[0..16], &expected_first_16);
}

/// RFC 8439 Section 2.4.2 - Test Vector for ChaCha20 Encryption
#[test]
fn test_chacha20_ietf_encrypt() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut plaintext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    ChaCha20::<CHACHA20_NONCE_SIZE>::default().crypt(&key, &nonce, 1, &mut plaintext);

    // First 16 bytes of expected ciphertext from RFC 8439
    let expected_first_16: [u8; 16] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81,
    ];
    assert_eq!(&plaintext[0..16], &expected_first_16);
}

// Bernstein variant tests (OpenSSH chacha20-poly1305@openssh.com)
//
// References:
// [1] draft-agl-tls-chacha20poly1305-04 (Adam Langley)
//     https://datatracker.ietf.org/doc/id/draft-agl-tls-chacha20poly1305-04.txt
// [2] Bernstein's original ChaCha paper (2008)
//     https://cr.yp.to/chacha/chacha-20080128.pdf
// [3] OpenSSH chacha20-poly1305 worked example
//     https://github.com/rus-cert/ssh-chacha20-poly1305-drafts

#[test]
fn test_chacha20_bernstein_zeroization_on_drop() {
    let chacha20: ChaCha20<CHACHA20_BERNSTEIN_NONCE_SIZE> = ChaCha20::default();

    assert!(chacha20.is_zeroized());
    chacha20.assert_zeroize_on_drop();
}

/// draft-agl-tls-chacha20poly1305-04 — Test Vectors 1-4
#[test]
fn test_chacha20_bernstein_vectors() {
    // Vector 1: all-zero key and nonce
    {
        let key = [0u8; 32];
        let nonce = [0u8; 8];
        let mut block = [0u8; 64];

        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().block(&key, &nonce, 0, &mut block);

        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];

        assert_eq!(
            &block, &expected,
            "Vector 1: all-zero key/nonce keystream mismatch"
        );
    }

    // Vector 2: key ends with 0x01
    {
        let mut key = [0u8; 32];
        key[31] = 0x01;
        let nonce = [0u8; 8];
        let mut block = [0u8; 64];

        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().block(&key, &nonce, 0, &mut block);

        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96,
            0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
            0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
            0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
            0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2,
            0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
            0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
            0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
        ];

        assert_eq!(&block, &expected, "Vector 2: key=0x01 keystream mismatch");
    }

    // Vector 3: nonce = 1
    {
        let key = [0u8; 32];
        let mut nonce = [0u8; 8];
        nonce[7] = 0x01;
        let mut block = [0u8; 64];

        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().block(&key, &nonce, 0, &mut block);

        #[rustfmt::skip]
        let expected_first_16: [u8; 16] = [
            0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5,
            0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
        ];

        assert_eq!(
            &block[0..16],
            &expected_first_16,
            "Vector 3: nonce=1 keystream mismatch"
        );
    }

    // Vector 4: incrementing key and nonce + roundtrip
    {
        #[rustfmt::skip]
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let mut block = [0u8; 64];
        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().block(&key, &nonce, 0, &mut block);

        #[rustfmt::skip]
        let expected_first_16: [u8; 16] = [
            0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69,
            0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
        ];

        assert_eq!(
            &block[0..16],
            &expected_first_16,
            "Vector 4: incrementing key/nonce keystream mismatch"
        );

        // Roundtrip: encrypt then decrypt
        let original = b"Bernstein ChaCha20 roundtrip test message for SSH!";
        let mut data = *original;

        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().crypt(&key, &nonce, 0, &mut data);
        assert_ne!(
            &data[..],
            &original[..],
            "Ciphertext should differ from plaintext"
        );

        ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default().crypt(&key, &nonce, 0, &mut data);
        assert_eq!(
            &data[..],
            &original[..],
            "Roundtrip should recover plaintext"
        );
    }
}

/// draft-irtf-cfrg-xchacha Section 2.2.1 - Test Vector for HChaCha20
#[test]
fn test_hchacha20() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 16] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];

    let mut subkey = [0u8; 32];
    HChaCha20::default().derive(&key, &nonce, &mut subkey);

    let expected: [u8; 32] = [
        0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d,
        0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3,
        0xec, 0xdc,
    ];
    assert_eq!(subkey, expected);
}

/// draft-irtf-cfrg-xchacha Appendix A.1 - Test Vector for XChaCha20-Poly1305
/// (we only test the XChaCha20 encryption part here, not the Poly1305 tag)
#[test]
fn test_xchacha20_encrypt() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let xnonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];

    let mut plaintext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    XChaCha20::default().crypt(&key, &xnonce, &mut plaintext);

    // Expected ciphertext from draft-irtf-cfrg-xchacha Appendix A.1
    let expected: [u8; 114] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
    ];
    assert_eq!(plaintext, expected);
}

/// Roundtrip test: encrypt then decrypt should return original plaintext
#[test]
fn test_xchacha20_roundtrip() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let original = b"Secret message that must survive roundtrip!";

    let mut data = *original;

    // Encrypt
    XChaCha20::default().crypt(&key, &xnonce, &mut data);
    assert_ne!(&data[..], &original[..]);

    // Decrypt (same operation)
    XChaCha20::default().crypt(&key, &xnonce, &mut data);
    assert_eq!(&data[..], &original[..]);
}

// Debug tests

#[test]
fn test_chacha20_ietf_debug_fmt() {
    let chacha20: ChaCha20<CHACHA20_NONCE_SIZE> = ChaCha20::default();
    let debug_str = format!("{:?}", chacha20);

    assert!(
        debug_str.contains("ChaCha20"),
        "Expected 'ChaCha20' in debug output"
    );
    assert!(
        debug_str.contains("[protected]"),
        "Expected '[protected]' to hide sensitive data"
    );
}

#[test]
fn test_chacha20_bernstein_debug_fmt() {
    let chacha20: ChaCha20<CHACHA20_BERNSTEIN_NONCE_SIZE> = ChaCha20::default();
    let debug_str = format!("{:?}", chacha20);

    assert!(debug_str.contains("ChaCha20"));
    assert!(debug_str.contains("[protected]"));
}

#[test]
fn test_hchacha20_debug_fmt() {
    let hchacha20 = HChaCha20::default();
    let debug_str = format!("{:?}", hchacha20);

    assert!(
        debug_str.contains("HChaCha20"),
        "Expected 'HChaCha20' in debug output"
    );
    assert!(
        debug_str.contains("[protected]"),
        "Expected '[protected]' to hide sensitive data"
    );
}

#[test]
fn test_xchacha20_debug_fmt() {
    let xchacha20 = XChaCha20::default();
    let debug_str = format!("{:?}", xchacha20);

    assert!(
        debug_str.contains("XChaCha20"),
        "Expected 'XChaCha20' in debug output"
    );
    assert!(
        debug_str.contains("[protected]"),
        "Expected '[protected]' to hide sensitive data"
    );
}
