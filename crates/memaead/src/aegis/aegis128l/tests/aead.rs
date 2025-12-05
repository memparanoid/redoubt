// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! High-level AEAD API tests with RFC vectors.

use memutil::hex_to_bytes;

use crate::aegis::aegis128l::aead::Aegis128L;
use crate::aegis::aegis128l::consts::{Aegis128LKey, Aegis128LNonce, Aegis128LTag};
use crate::AeadBackend;

/// A.2.4 - Test Vector 3 via high-level API (32-byte msg, 8-byte ad)
#[test]
fn test_aead_vector_3() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("0001020304050607");
    let msg = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let expected_ct =
        hex_to_bytes("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84");
    let expected_tag: Aegis128LTag = hex_to_bytes("cc6f3372f6aa1bb82388d695c3962d9a")
        .try_into()
        .unwrap();

    let mut aead = Aegis128L::default();
    let mut data = msg.clone();
    let mut tag = [0u8; 16];

    aead.encrypt(&key, &nonce, &ad, &mut data, &mut tag);

    assert_eq!(&data[..], &expected_ct[..], "AEAD ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "AEAD tag mismatch");
}

/// A.2.5 - Test Vector 4 via high-level API (13-byte msg, partial block)
#[test]
fn test_aead_vector_4_partial() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("0001020304050607");
    let msg = hex_to_bytes("000102030405060708090a0b0c0d");
    let expected_ct = hex_to_bytes("79d94593d8c2119d7e8fd9b8fc77");
    let expected_tag: Aegis128LTag = hex_to_bytes("5c04b3dba849b2701effbe32c7f0fab7")
        .try_into()
        .unwrap();

    let mut aead = Aegis128L::default();
    let mut data = msg.clone();
    let mut tag = [0u8; 16];

    aead.encrypt(&key, &nonce, &ad, &mut data, &mut tag);

    assert_eq!(&data[..], &expected_ct[..], "AEAD partial ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "AEAD partial tag mismatch");
}

/// A.2.6 - Test Vector 5 via high-level API (longer msg and ad)
#[test]
fn test_aead_vector_5_longer() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829");
    let msg = hex_to_bytes("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    let expected_ct = hex_to_bytes("b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10");
    let expected_tag: Aegis128LTag = hex_to_bytes("7542a745733014f9474417b337399507")
        .try_into()
        .unwrap();

    let mut aead = Aegis128L::default();
    let mut data = msg.clone();
    let mut tag = [0u8; 16];

    aead.encrypt(&key, &nonce, &ad, &mut data, &mut tag);

    assert_eq!(&data[..], &expected_ct[..], "AEAD longer ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "AEAD longer tag mismatch");
}

/// AEAD roundtrip test
#[test]
fn test_aead_roundtrip() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("0001020304050607");
    let plaintext = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let mut aead = Aegis128L::default();
    let mut data = plaintext.clone();
    let mut tag = [0u8; 16];

    // Encrypt
    aead.encrypt(&key, &nonce, &ad, &mut data, &mut tag);

    // Decrypt
    let result = aead.decrypt(&key, &nonce, &ad, &mut data, &tag);
    assert!(result.is_ok(), "Decryption should succeed");
    assert_eq!(&data[..], &plaintext[..], "AEAD roundtrip plaintext mismatch");
}

/// AEAD authentication failure test (modified ciphertext)
#[test]
fn test_aead_auth_failure() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("0001020304050607");
    let plaintext = hex_to_bytes("000102030405060708090a0b0c0d0e0f");

    let mut aead = Aegis128L::default();
    let mut data = plaintext.clone();
    let mut tag = [0u8; 16];

    // Encrypt
    aead.encrypt(&key, &nonce, &ad, &mut data, &mut tag);

    // Modify ciphertext
    data[0] ^= 1;

    // Decrypt should fail
    let result = aead.decrypt(&key, &nonce, &ad, &mut data, &tag);
    assert!(result.is_err(), "Decryption should fail with modified ciphertext");
}

/// A.2.3 - Test Vector 2 via high-level API (empty msg, no ad)
#[test]
fn test_aead_empty_msg() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: Aegis128LKey = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: Aegis128LNonce = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let expected_tag: Aegis128LTag = hex_to_bytes("c2b879a67def9d74e6c14f708bbcc9b4")
        .try_into()
        .unwrap();

    let mut aead = Aegis128L::default();
    let mut data: Vec<u8> = vec![];
    let mut tag = [0u8; 16];

    aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert_eq!(&tag[..], &expected_tag[..], "AEAD empty msg tag mismatch");
}
