// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! State function tests with RFC vectors.

use memutil::hex_to_bytes;
use crate::aegis::aegis128l::state;

/// A.2.2 - Test Vector 1 (16-byte msg, no ad)
#[test]
fn test_vector_1_16byte_msg_no_ad() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: [u8; 16] = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to key");
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to nonce");
    let mut msg = hex_to_bytes("00000000000000000000000000000000");
    let expected_ct = hex_to_bytes("c1c0e58bd913006feba00f4b3cc3594e");
    let expected_tag: [u8; 16] = hex_to_bytes("abe0ece80c24868a226a35d16bdae37a")
        .try_into()
        .expect("Failed to convert hex to tag");

    let mut tag = [0u8; 16];

    unsafe {
        state::encrypt(&key, &nonce, &[], &mut msg, &mut tag);
    }

    assert_eq!(&msg[..], &expected_ct[..], "Ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch");
}

/// A.2.3 - Test Vector 2 (empty msg, no ad)
#[test]
fn test_vector_2_empty_msg_no_ad() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: [u8; 16] = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to key");
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to nonce");
    let expected_tag: [u8; 16] = hex_to_bytes("c2b879a67def9d74e6c14f708bbcc9b4")
        .try_into()
        .expect("Failed to convert hex to tag");

    let mut data = [];
    let mut tag = [0u8; 16];

    unsafe {
        state::encrypt(&key, &nonce, &[], &mut data, &mut tag);
    }

    assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch for empty message");
}

/// A.2.4 - Test Vector 3 (32-byte msg, 8-byte ad)
#[test]
fn test_vector_3_32byte_msg_8byte_ad() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: [u8; 16] = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to key");
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to nonce");
    let ad = hex_to_bytes("0001020304050607");
    let mut msg =
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let expected_ct =
        hex_to_bytes("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84");
    let expected_tag: [u8; 16] = hex_to_bytes("cc6f3372f6aa1bb82388d695c3962d9a")
        .try_into()
        .expect("Failed to convert hex to tag");

    let mut tag = [0u8; 16];

    unsafe {
        state::encrypt(&key, &nonce, &ad, &mut msg, &mut tag);
    }

    assert_eq!(&msg[..], &expected_ct[..], "Ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch");
}

/// Test encrypt then decrypt roundtrip
#[test]
fn test_encrypt_decrypt_roundtrip() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: [u8; 16] = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to key");
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .expect("Failed to convert hex to nonce");
    let plaintext: [u8; 32] =
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .expect("Failed to convert hex to plaintext");

    let mut data = plaintext;
    let mut tag = [0u8; 16];

    unsafe {
        // Encrypt
        state::encrypt(&key, &nonce, &[], &mut data, &mut tag);

        // Decrypt
        let ok = state::decrypt(&key, &nonce, &[], &mut data, &tag);
        assert!(ok, "Decryption failed");
    }

    assert_eq!(data, plaintext, "Roundtrip plaintext mismatch");
}
