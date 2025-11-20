// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memzer::{AssertZeroizeOnDrop, Secret, ZeroizationProbe};

use crate::aead_key::AeadKey;
use crate::guards::{DecryptionMemZer, EncryptionMemZer};
use crate::xnonce::XNonce;

use super::support::MemCodeTestBreaker;

#[test]
fn test_encryption_mem_guard() {
    let mut aead_key = AeadKey::from([u8::MAX; 32]);
    let mut xnonce = XNonce::from([u8::MAX; 24]);

    let mut test_breaker = MemCodeTestBreaker::default();

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut xnonce, &mut test_breaker);

    assert!(!x.is_zeroized());

    x.zeroize();

    // Assert zeroization!
    assert!(x.is_zeroized());

    x.assert_zeroize_on_drop();
}

#[test]
fn test_decryption_mem_guard() {
    let mut aead_key = AeadKey::from([u8::MAX; 32]);
    let mut xnonce = XNonce::from([u8::MAX; 24]);

    let mut ciphertext = Secret::from(vec![1u8; 64]);

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    assert!(!x.is_zeroized());

    x.zeroize();

    // Assert zeroization!
    assert!(x.is_zeroized());

    x.assert_zeroize_on_drop();
}
