// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for AeadMock.
use redoubt_zero::ZeroizationProbe;

use crate::error::AeadError;
use crate::support::test_utils::{AeadMock, AeadMockBehaviour};
use crate::traits::AeadApi;

// =============================================================================
// new()
// =============================================================================

#[test]
fn test_new_returns_valid_mock() {
    let mock = AeadMock::new(AeadMockBehaviour::None);
    assert_eq!(mock.key_size(), AeadMock::KEY_SIZE);
    assert_eq!(mock.nonce_size(), AeadMock::NONCE_SIZE);
    assert_eq!(mock.tag_size(), AeadMock::TAG_SIZE);
}

// =============================================================================
// encrypt()
// =============================================================================

#[test]
fn test_encrypt_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let original = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut data = original;
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to encrypt(..)");

    assert_ne!(data, original);
}

#[test]
fn test_encrypt_fails_at_index() {
    let mut mock = AeadMock::new(AeadMockBehaviour::FailEncryptAt(2));
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut data = [1, 2, 3, 4];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
    assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
    assert!(
        mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
            .is_err()
    );
    assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
}

// =============================================================================
// decrypt()
// =============================================================================

#[test]
fn test_decrypt_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let original = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut data = original;
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to encrypt(..)");

    mock.decrypt(&key, &nonce, &[], &mut data, &tag)
        .expect("Failed to decrypt(..)");

    assert_eq!(data, original);
}

#[test]
fn test_decrypt_fails_at_index() {
    let mut mock = AeadMock::new(AeadMockBehaviour::FailDecryptAt(1));
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let data = [1u8, 2, 3, 4];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut original_ciphertext = data;
    mock.encrypt(&key, &nonce, &[], &mut original_ciphertext, &mut tag)
        .expect("Failed to encrypt(..)");

    let mut ciphertext = [0u8; 4];
    assert!(ciphertext.is_zeroized());

    // Call 0
    ciphertext = original_ciphertext;
    assert!(!ciphertext.is_zeroized());
    assert!(
        mock.decrypt(&key, &nonce, &[], &mut ciphertext, &tag)
            .is_ok()
    );

    // Call 1
    // Should fail because of FailDecryptAt 1.
    ciphertext = original_ciphertext;
    assert!(!ciphertext.is_zeroized());
    assert!(
        mock.decrypt(&key, &nonce, &[], &mut ciphertext, &tag)
            .is_err()
    );

    // Call 2
    ciphertext = original_ciphertext;
    assert!(!ciphertext.is_zeroized());
    assert!(
        mock.decrypt(&key, &nonce, &[], &mut ciphertext, &tag)
            .is_ok()
    );
}

// =============================================================================
// generate_nonce()
// =============================================================================

#[test]
fn test_generate_nonce_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);

    let nonce = mock.generate_nonce().expect("Failed to generate_nonce()");

    assert_eq!(nonce.len(), AeadMock::NONCE_SIZE);
}

#[test]
fn test_generate_nonce_fails_at_index() {
    let mut mock = AeadMock::new(AeadMockBehaviour::FailGenerateNonceAt(0));

    assert!(mock.generate_nonce().is_err());
    assert!(mock.generate_nonce().is_ok());
}

// =============================================================================
// api_encrypt()
// =============================================================================

#[test]
fn test_api_encrypt_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let original = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut data = original;
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to api_encrypt(..)");

    assert_ne!(data, original);
}

#[test]
fn test_api_encrypt_propagates_invalid_key_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE - 1];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    let result = mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[test]
fn test_api_encrypt_propagates_invalid_nonce_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE - 1];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    let result = mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[test]
fn test_api_encrypt_propagates_invalid_tag_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut tag = [0u8; AeadMock::TAG_SIZE - 1];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    let result = mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

// =============================================================================
// api_decrypt()
// =============================================================================

#[test]
fn test_api_decrypt_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let original = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut data = original;
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to api_encrypt(..)");

    mock.api_decrypt(&key, &nonce, &[], &mut data, &tag)
        .expect("Failed to api_decrypt(..)");

    assert_eq!(data, original);
}

#[test]
fn test_api_decrypt_propagates_invalid_key_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to api_encrypt(..)");

    let result = mock.api_decrypt(
        &key[0..AeadMock::KEY_SIZE - 1],
        &nonce,
        &[],
        &mut data,
        &tag,
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[test]
fn test_api_decrypt_propagates_invalid_nonce_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to api_encrypt(..)");

    let result = mock.api_decrypt(
        &key,
        &nonce[0..AeadMock::NONCE_SIZE - 1],
        &[],
        &mut data,
        &tag,
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[test]
fn test_api_decrypt_propagates_invalid_tag_size_error() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);
    let key = [0u8; AeadMock::KEY_SIZE];
    let nonce = [0u8; AeadMock::NONCE_SIZE];
    let mut tag = [0u8; AeadMock::TAG_SIZE];

    let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    mock.api_encrypt(&key, &nonce, &[], &mut data, &mut tag)
        .expect("Failed to api_encrypt(..)");

    let result = mock.api_decrypt(
        &key,
        &nonce,
        &[],
        &mut data,
        &tag[0..AeadMock::TAG_SIZE - 1],
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

// =============================================================================
// api_generate_nonce()
// =============================================================================

#[test]
fn test_api_generate_nonce_succeeds() {
    let mut mock = AeadMock::new(AeadMockBehaviour::None);

    let nonce = mock
        .api_generate_nonce()
        .expect("Failed to api_generate_nonce()");

    assert_eq!(nonce.len(), AeadMock::NONCE_SIZE);
}

// =============================================================================
// api_key_size()
// =============================================================================

#[test]
fn test_api_key_size_returns_correct_size() {
    let mock = AeadMock::new(AeadMockBehaviour::None);
    assert_eq!(mock.api_key_size(), 32);
}

// =============================================================================
// api_nonce_size()
// =============================================================================

#[test]
fn test_api_nonce_size_returns_correct_size() {
    let mock = AeadMock::new(AeadMockBehaviour::None);
    assert_eq!(mock.api_nonce_size(), 24);
}

// =============================================================================
// api_tag_size()
// =============================================================================

#[test]
fn test_api_tag_size_returns_correct_size() {
    let mock = AeadMock::new(AeadMockBehaviour::None);
    assert_eq!(mock.api_tag_size(), 16);
}
