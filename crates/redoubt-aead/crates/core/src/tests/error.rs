// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error::Error;

use rstest::rstest;

use crate::error::AeadCoreError;

// ============================================================================
// AeadCoreError: Display
// ============================================================================

#[rstest]
#[case::authentication_failed(
    AeadCoreError::AuthenticationFailed,
    "the tag does not match: the ciphertext was changed, or sealed with another key"
)]
#[case::invalid_key_size(
    AeadCoreError::InvalidKeySize,
    "the key is not the width this cipher takes"
)]
#[case::invalid_nonce_size(
    AeadCoreError::InvalidNonceSize,
    "the nonce is not the width this cipher takes"
)]
#[case::invalid_tag_size(
    AeadCoreError::InvalidTagSize,
    "the tag is not the width this cipher takes"
)]
#[case::entropy_not_available(AeadCoreError::EntropyNotAvailable, "the system gave no entropy")]
#[case::injected(AeadCoreError::Injected, "a test behaviour refused this operation")]
fn test_aead_core_error_says_what_happened(#[case] error: AeadCoreError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// AeadCoreError: Error::source
// ============================================================================

#[rstest]
#[case::authentication_failed(AeadCoreError::AuthenticationFailed)]
#[case::invalid_key_size(AeadCoreError::InvalidKeySize)]
#[case::invalid_nonce_size(AeadCoreError::InvalidNonceSize)]
#[case::invalid_tag_size(AeadCoreError::InvalidTagSize)]
#[case::entropy_not_available(AeadCoreError::EntropyNotAvailable)]
#[case::injected(AeadCoreError::Injected)]
fn test_aead_core_error_source_returns_none(#[case] error: AeadCoreError) {
    assert!(error.source().is_none());
}
