// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD unit tests

use redoubt_zero::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::AeadError;
use crate::traits::AeadBackend;
use crate::xchacha20poly1305::XChacha20Poly1305;
use crate::xchacha20poly1305::consts::TAG_SIZE;

#[test]
fn test_aead_zeroization_on_drop() {
    let aead = XChacha20Poly1305::default();

    assert!(aead.is_zeroized());
    aead.assert_zeroize_on_drop();
}

/// draft-irtf-cfrg-xchacha Appendix A.1 - Full AEAD test vector
#[test]
fn test_xchacha20_poly1305_encrypt() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let xnonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let mut data = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, &aad, &mut data, &mut tag);

    // Expected ciphertext (114 bytes)
    let expected_ct: [u8; 114] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
    ];
    let expected_tag: [u8; 16] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf,
        0x49,
    ];

    assert_eq!(&data, &expected_ct);
    assert_eq!(&tag, &expected_tag);
}

#[test]
fn test_xchacha20_poly1305_decrypt() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let xnonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];

    // Ciphertext (114 bytes)
    let mut data: [u8; 114] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
    ];
    // Tag (16 bytes)
    let tag: [u8; TAG_SIZE] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf,
        0x49,
    ];

    let mut aead = XChacha20Poly1305::default();
    aead.decrypt(&key, &xnonce, &aad, &mut data, &tag)
        .expect("decryption failed");

    assert_eq!(
        &data,
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
}

#[test]
fn test_modified_tag_rejected() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let aad = b"header";
    let mut data = *b"secret";
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, aad, &mut data, &mut tag);

    // Flip one bit in the tag
    tag[TAG_SIZE - 1] ^= 0x01;

    // Should fail authentication
    let result = aead.decrypt(&key, &xnonce, aad, &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::AuthenticationFailed)));

    // Ciphertext must be zeroized on auth failure
    assert!(data.is_zeroized());
}

#[test]
fn test_modified_ciphertext_rejected() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let aad = b"header";
    let mut data = *b"secret";
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, aad, &mut data, &mut tag);

    // Flip one bit in the ciphertext (not tag)
    data[0] ^= 0x01;

    // Should fail authentication
    let result = aead.decrypt(&key, &xnonce, aad, &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::AuthenticationFailed)));

    // Ciphertext must be zeroized on auth failure
    assert!(data.is_zeroized());
}

#[test]
fn test_modified_aad_rejected() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let mut data = *b"secret";
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, b"header", &mut data, &mut tag);

    // Different AAD should fail
    let result = aead.decrypt(&key, &xnonce, b"HEADER", &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::AuthenticationFailed)));

    // Ciphertext must be zeroized on auth failure
    assert!(data.is_zeroized());
}

#[test]
fn test_roundtrip() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let aad = b"associated data";
    let original = b"Hello, XChaCha20-Poly1305!";
    let mut data = *original;
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, aad, &mut data, &mut tag);

    // data now contains ciphertext
    assert_ne!(&data, original);

    // Decrypt in-place
    aead.decrypt(&key, &xnonce, aad, &mut data, &tag)
        .expect("decryption failed");

    assert_eq!(&data, original);
}

#[test]
fn test_empty_plaintext() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let aad = b"just aad, no plaintext";
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, aad, &mut [], &mut tag);

    // Decrypt empty ciphertext
    aead.decrypt(&key, &xnonce, aad, &mut [], &tag)
        .expect("decryption failed");
}

#[test]
fn test_empty_aad() {
    let key = [0x42u8; 32];
    let xnonce = [0x24u8; 24];
    let original = b"no associated data";
    let mut data = *original;
    let mut tag = [0u8; TAG_SIZE];

    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(&key, &xnonce, b"", &mut data, &mut tag);

    // data now contains ciphertext
    assert_ne!(&data, original);

    // Decrypt in-place
    aead.decrypt(&key, &xnonce, b"", &mut data, &tag)
        .expect("decryption failed");

    assert_eq!(&data, original);
}

// Debug test

#[test]
fn test_xchacha20poly1305_debug_fmt() {
    let aead = XChacha20Poly1305::default();
    let debug_str = format!("{:?}", aead);

    assert!(
        debug_str.contains("XChacha20Poly1305"),
        "Expected 'XChacha20Poly1305' in debug output"
    );
    assert!(
        debug_str.contains("[protected]"),
        "Expected '[protected]' to hide sensitive data"
    );
}

/// Test that generate_nonce() produces unique nonces
#[test]
fn test_generate_nonce_uniqueness() {
    let mut aead = XChacha20Poly1305::default();

    let nonce1 = aead.generate_nonce().expect("Failed to generate nonce #1");
    let nonce2 = aead.generate_nonce().expect("Failed to generate nonce #2");
    let nonce3 = aead.generate_nonce().expect("Failed to generate nonce #3");
    let nonce4 = aead.generate_nonce().expect("Failed to generate nonce #4");

    // All nonces should be distinct
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce1, nonce3);
    assert_ne!(nonce1, nonce4);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce2, nonce4);
    assert_ne!(nonce3, nonce4);
}
