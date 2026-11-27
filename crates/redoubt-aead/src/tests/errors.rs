// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error::Error;

use rstest::rstest;

use redoubt_aead_core::AeadCoreError;
use redoubt_rand::EntropyError;

use crate::enums::AeadAlgorithm;
use crate::errors::AeadError;

// ============================================================================
// AeadError: Display
// ============================================================================

#[rstest]
#[case::core(
    AeadError::Core(AeadCoreError::InvalidKeySize),
    "the key is not the width this cipher takes"
)]
#[case::nonce_entropy(
    AeadError::NonceEntropy(EntropyError::EntropyNotAvailable),
    "no nonce could be generated: the system gave no entropy"
)]
#[case::key_width(
    AeadError::KeyWidth { algorithm: AeadAlgorithm::Aegis128L, expected: 16, given: 32 },
    "Aegis128L seals with a key of 16 bytes and was handed 32"
)]
#[case::nonce_width(
    AeadError::NonceWidth { algorithm: AeadAlgorithm::XChachaPoly1305, expected: 24, given: 12 },
    "XChachaPoly1305 seals with a nonce of 24 bytes and was handed 12"
)]
#[case::tag_width(
    AeadError::TagWidth { algorithm: AeadAlgorithm::Aegis128L, expected: 16, given: 15 },
    "Aegis128L writes a tag of 16 bytes and was handed 15"
)]
fn test_aead_error_says_what_happened(#[case] error: AeadError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// AeadError: Error::source
// ============================================================================

#[rstest]
#[case::core(AeadError::Core(AeadCoreError::InvalidKeySize))]
#[case::nonce_entropy(AeadError::NonceEntropy(EntropyError::EntropyNotAvailable))]
#[case::key_width(AeadError::KeyWidth { algorithm: AeadAlgorithm::Aegis128L, expected: 16, given: 32 })]
#[case::nonce_width(AeadError::NonceWidth { algorithm: AeadAlgorithm::XChachaPoly1305, expected: 24, given: 12 })]
#[case::tag_width(AeadError::TagWidth { algorithm: AeadAlgorithm::Aegis128L, expected: 16, given: 15 })]
fn test_aead_error_source_returns_none(#[case] error: AeadError) {
    assert!(error.source().is_none());
}
