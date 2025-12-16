// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::generate_random_key::generate_random_key;

#[test]
fn generates_key_with_correct_size() {
    let mut key16 = [0u8; 16];
    generate_random_key(b"test.key.16", &mut key16).expect("Failed to generate 16-byte key");
    assert_eq!(key16.len(), 16);

    let mut key32 = [0u8; 32];
    generate_random_key(b"test.key.32", &mut key32).expect("Failed to generate 32-byte key");
    assert_eq!(key32.len(), 32);

    let mut key64 = [0u8; 64];
    generate_random_key(b"test.key.64", &mut key64).expect("Failed to generate 64-byte key");
    assert_eq!(key64.len(), 64);
}

#[test]
fn generates_unique_keys() {
    let mut key1 = [0u8; 32];
    generate_random_key(b"test.key.1", &mut key1).expect("Failed to generate key 1");

    let mut key2 = [0u8; 32];
    generate_random_key(b"test.key.2", &mut key2).expect("Failed to generate key 2");

    // Statistically, two randomly generated 32-byte keys should never collide
    assert_ne!(key1, key2, "Keys must be unique");
}

#[test]
fn different_info_produces_different_keys() {
    let mut key_a = [0u8; 32];
    generate_random_key(b"context.a", &mut key_a).expect("Failed to generate key A");

    let mut key_b = [0u8; 32];
    generate_random_key(b"context.b", &mut key_b).expect("Failed to generate key B");

    assert_ne!(key_a, key_b, "Different info should produce different keys");
}

#[test]
fn generates_nonzero_keys() {
    let mut key = [0u8; 32];
    generate_random_key(b"test.nonzero", &mut key).expect("Failed to generate key");

    // Probability of generating an all-zero 32-byte key is 1/2^256 (negligible)
    assert_ne!(key, [0u8; 32], "Key must not be all zeros");
}

#[test]
fn supports_various_key_sizes() {
    // Test common cryptographic key sizes
    let mut key_aes128 = [0u8; 16];
    generate_random_key(b"aes128", &mut key_aes128).expect("AES-128 key generation failed");

    let mut key_aes256 = [0u8; 32];
    generate_random_key(b"xchacha20", &mut key_aes256).expect("XChaCha20 key generation failed");

    let mut key_hmac512 = [0u8; 64];
    generate_random_key(b"hmac512", &mut key_hmac512).expect("HMAC-SHA512 key generation failed");

    // Test edge cases
    let mut key_tiny = [0u8; 1];
    generate_random_key(b"tiny", &mut key_tiny).expect("1-byte key generation failed");

    let mut key_large = [0u8; 128];
    generate_random_key(b"large", &mut key_large).expect("128-byte key generation failed");
}

#[test]
fn info_provides_domain_separation() {
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
