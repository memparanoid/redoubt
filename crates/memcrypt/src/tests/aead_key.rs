// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::Key;

use crate::aead_key::AeadKey;

use memzer::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

#[test]
fn test_aead_key_memguard_traits() {
    let mut key = AeadKey::default();
    key.fill_exact(&mut [u8::MAX; 32]);

    // Assert (not) zeroization!
    assert!(!key.is_zeroized());

    key.self_zeroize();

    // Assert zeroization!
    assert!(key.is_zeroized());

    key.assert_zeroize_on_drop();
}

#[test]
fn test_aead_key_from() {
    let nonce = AeadKey::from([2u8; 32]);
    assert_eq!(nonce.as_ref(), &[2u8; 32]);
}

#[test]
fn test_aead_key_as_ref() {
    let key = AeadKey::from([1u8; 32]);

    fn with_ref(key: &Key) -> bool {
        key.len() == 32
    }

    assert!(with_ref(key.as_ref()));
}

#[test]
fn test_aead_key_fill_exact() {
    let mut key = AeadKey::default();

    let mut bytes = [1u8; 32];
    key.fill_exact(&mut bytes);

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));

    assert_eq!(key, AeadKey::from([1u8; 32]));
}

#[test]
fn test_debug_does_not_expose_contents() {
    let key = AeadKey::default();
    let str = format!("{:?}", key);

    assert!(str.contains("AeadKey") && str.contains("protected"));
    assert!(!str.contains("AB"), "Debug must not leak raw bytes");
}
