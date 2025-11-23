// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::guards::{DecryptionMemZer, EncryptionMemZer};

use super::support::{MemCodeTestBreaker, create_key_from_array, create_xnonce_from_array};

#[test]
fn test_encryption_mem_guard() {
    let mut aead_key = create_key_from_array([u8::MAX; 32]);
    let mut xnonce = create_xnonce_from_array([u8::MAX; 24]);

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
    let mut aead_key = create_key_from_array([u8::MAX; 32]);
    let mut xnonce = create_xnonce_from_array([u8::MAX; 24]);

    let mut ciphertext = vec![1u8; 64];

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    assert!(!x.is_zeroized());

    x.zeroize();

    // Assert zeroization!
    assert!(x.is_zeroized());

    x.assert_zeroize_on_drop();
}
