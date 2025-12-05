// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::support::test_utils::TestBreaker;
use memzer::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::guards::{DecryptionMemZer, EncryptionMemZer};

use super::utils::{create_aead_key, create_nonce};

#[test]
fn test_encryption_mem_guard() {
    let aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, u8::MAX);
    let mut nonce = create_nonce(&aead, u8::MAX);

    let mut test_breaker = TestBreaker::default();

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);

    assert!(!x.is_zeroized());

    x.fast_zeroize();

    // Assert zeroization!
    assert!(x.is_zeroized());

    x.assert_zeroize_on_drop();
}

#[test]
fn test_decryption_mem_guard() {
    let aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, u8::MAX);
    let mut nonce = create_nonce(&aead, u8::MAX);

    let mut ciphertext = vec![1u8; 64];

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut nonce, &mut ciphertext);

    assert!(!x.is_zeroized());

    x.fast_zeroize();

    // Assert zeroization!
    assert!(x.is_zeroized());

    x.assert_zeroize_on_drop();
}
