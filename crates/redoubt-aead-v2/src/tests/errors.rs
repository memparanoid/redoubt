// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::string::ToString;

use crate::errors::{AeadError, AeadOperation};

// === === === === === === === === === ===
// fmt
// === === === === === === === === === ===

#[test]
fn test_fmt_writes_the_encrypt_operation() {
    assert_eq!(AeadOperation::Encrypt.to_string(), "encrypt");
}

#[test]
fn test_fmt_writes_the_decrypt_operation() {
    assert_eq!(AeadOperation::Decrypt.to_string(), "decrypt");
}

#[test]
fn test_fmt_writes_the_generate_nonce_operation() {
    assert_eq!(AeadOperation::GenerateNonce.to_string(), "generate_nonce");
}

#[test]
fn test_fmt_writes_a_different_name_for_every_operation() {
    let encrypt = AeadOperation::Encrypt.to_string();
    let decrypt = AeadOperation::Decrypt.to_string();
    let nonce = AeadOperation::GenerateNonce.to_string();

    assert_ne!(encrypt, decrypt);
    assert_ne!(decrypt, nonce);
    assert_ne!(nonce, encrypt);
}

// === === === === === === === === === ===
// Injected
// === === === === === === === === === ===

/// `{0}` reaches the payload's `Display` and not its `Debug`. Written the other
/// way the message still names the operation — as `Encrypt` — so only the exact
/// string tells them apart.
#[test]
fn test_injected_names_the_operation_it_refused() {
    assert_eq!(
        AeadError::Injected(AeadOperation::Encrypt).to_string(),
        "a test behaviour refused encrypt"
    );
}

#[test]
fn test_injected_names_a_different_operation_for_each_variant() {
    let encrypt = AeadError::Injected(AeadOperation::Encrypt).to_string();
    let decrypt = AeadError::Injected(AeadOperation::Decrypt).to_string();

    assert_ne!(
        encrypt, decrypt,
        "an injected failure reads the same whichever call it refused"
    );
}
