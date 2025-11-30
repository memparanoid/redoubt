// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Low-level state tests with RFC vectors.

use memutil::hex_to_bytes;

use crate::aegis::aegis128l::state::Aegis128LState;

/// A.2.2 - Test Vector 1 (16-byte msg, no ad)
#[test]
fn test_vector_1_16byte_msg_no_ad() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let key: [u8; 16] = hex_to_bytes("10010000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let msg = hex_to_bytes("00000000000000000000000000000000");
    let expected_ct = hex_to_bytes("c1c0e58bd913006feba00f4b3cc3594e");
    let expected_tag = hex_to_bytes("abe0ece80c24868a226a35d16bdae37a");

    let mut state = Aegis128LState::default();
    let mut data = [0u8; 16];
    data.copy_from_slice(&msg);

    unsafe {
        state.init(&key, &nonce);
        // 16-byte message is a partial block (< 32 bytes)
        state.encrypt_partial(&mut data);

        let mut tag = [0u8; 16];
        state.finalize(0, 16, &mut tag);

        assert_eq!(&data[..], &expected_ct[..], "Ciphertext mismatch");
        assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch");
    }
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
        .unwrap();
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let expected_tag = hex_to_bytes("c2b879a67def9d74e6c14f708bbcc9b4");

    let mut state = Aegis128LState::default();

    unsafe {
        state.init(&key, &nonce);

        let mut tag = [0u8; 16];
        state.finalize(0, 0, &mut tag);

        assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch for empty message");
    }
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
        .unwrap();
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let ad = hex_to_bytes("0001020304050607");
    let msg = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let expected_ct =
        hex_to_bytes("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84");
    let expected_tag = hex_to_bytes("cc6f3372f6aa1bb82388d695c3962d9a");

    let mut state = Aegis128LState::default();
    let mut block: [u8; 32] = msg.try_into().unwrap();

    unsafe {
        state.init(&key, &nonce);
        // absorb_all handles padding internally
        state.absorb_all(&ad);
        // 32-byte message is exactly one full block
        state.encrypt_blocks(&mut block);

        let mut tag = [0u8; 16];
        state.finalize(ad.len(), 32, &mut tag);

        assert_eq!(&block[..], &expected_ct[..], "Ciphertext mismatch");
        assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch");
    }
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
        .unwrap();
    let nonce: [u8; 16] = hex_to_bytes("10000200000000000000000000000000")
        .try_into()
        .unwrap();
    let plaintext: [u8; 32] =
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();

    let mut encrypt_state = Aegis128LState::default();
    let mut decrypt_state = Aegis128LState::default();

    let mut block = plaintext;

    unsafe {
        // Encrypt
        encrypt_state.init(&key, &nonce);
        encrypt_state.encrypt_blocks(&mut block);
        let mut tag = [0u8; 16];
        encrypt_state.finalize(0, 32, &mut tag);

        // Decrypt
        decrypt_state.init(&key, &nonce);
        decrypt_state.decrypt_blocks(&mut block);
        let mut dec_tag = [0u8; 16];
        decrypt_state.finalize(0, 32, &mut dec_tag);

        assert_eq!(block, plaintext, "Roundtrip plaintext mismatch");
        assert_eq!(tag, dec_tag, "Tag mismatch after roundtrip");
    }
}
