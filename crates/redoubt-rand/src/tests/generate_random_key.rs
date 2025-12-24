// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::generate_random_key::generate_random_key;

#[test]
fn test_generate_random_key_supports_empty_key() {
    let mut empty = [];
    let result = generate_random_key(b"test.empty", &mut empty);

    assert!(result.is_ok());
}

#[test]
fn test_generate_random_key_supports_common_key_sizes() {
    // Verify function succeeds for typical cryptographic key sizes
    let mut key16 = [0u8; 16];
    generate_random_key(b"test.aes128", &mut key16).expect("16-byte key failed");

    let mut key32 = [0u8; 32];
    generate_random_key(b"test.xchacha20", &mut key32).expect("32-byte key failed");

    let mut key64 = [0u8; 64];
    generate_random_key(b"test.hmac512", &mut key64).expect("64-byte key failed");

    // Edge cases
    let mut key1 = [0u8; 1];
    generate_random_key(b"test.tiny", &mut key1).expect("1-byte key failed");

    let mut key128 = [0u8; 128];
    generate_random_key(b"test.large", &mut key128).expect("128-byte key failed");
}

#[test]
fn test_generate_random_key_info_provides_domain_separation() {
    let mut master_key = [0u8; 32];
    generate_random_key(b"app.master_key.v1", &mut master_key)
        .expect("Failed to generate master key");

    let mut encryption_key = [0u8; 32];
    generate_random_key(b"app.encryption_key.v1", &mut encryption_key)
        .expect("Failed to generate encryption key");

    let mut signing_key = [0u8; 32];
    generate_random_key(b"app.signing_key.v1", &mut signing_key)
        .expect("Failed to generate signing key");

    // All keys must be different due to info parameter
    assert_ne!(master_key, encryption_key);
    assert_ne!(master_key, signing_key);
    assert_ne!(encryption_key, signing_key);
}
