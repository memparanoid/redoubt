// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::XNonce as ChaCha20Poly1305XNonce;

use memguard::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

use crate::xnonce::XNonce;

#[test]
fn test_xnonce_memguard_traits() {
    let mut nonce = XNonce::default();
    nonce.fill_exact(&mut [u8::MAX; 24]);

    // Assert (not) zeroization!
    assert!(!nonce.is_zeroized());

    nonce.self_zeroize();

    // Assert zeroization!
    assert!(nonce.is_zeroized());

    nonce.assert_zeroize_on_drop();
}

#[test]
fn test_xnonce_from() {
    let nonce = XNonce::from([2u8; 24]);
    assert_eq!(nonce.as_ref(), &[2u8; 24]);
}

#[test]
fn test_xnonce_as_ref() {
    let nonce = XNonce::from([1u8; 24]);

    fn with_ref(nonce: &ChaCha20Poly1305XNonce) -> bool {
        nonce.len() == 24
    }

    assert!(with_ref(nonce.as_ref()));
}

#[test]
fn test_xnonce_fill_exact() {
    let mut nonce = XNonce::default();

    let mut bytes = [1u8; 24];
    nonce.fill_exact(&mut bytes);

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));

    assert_eq!(nonce, XNonce::from([1u8; 24]));
}
