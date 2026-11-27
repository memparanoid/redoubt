// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::error::Error;

use rstest::rstest;

use redoubt_aead::{AeadCoreError, AeadError};
use redoubt_buffer::BufferError;
use redoubt_codec::{DecodeError, EncodeError, OverflowError};

use crate::error::CipherBoxError;
use crate::master_key::TruncationTooWide;

#[derive(Debug)]
struct Cause;

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the callback's own cause")
    }
}

impl Error for Cause {}

#[derive(Debug)]
struct Refused(Cause);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a test callback refused")
    }
}

impl Error for Refused {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

fn overflow_error() -> OverflowError {
    OverflowError {
        reason: "a reason".into(),
    }
}

// ============================================================================
// CipherBoxError: Display
// ============================================================================

#[rstest]
#[case::overflow(
    CipherBoxError::Overflow(overflow_error()),
    "the encoded size would be past usize::MAX: a reason"
)]
#[case::encode(
    CipherBoxError::Encode(EncodeError::IntentionalEncodeError),
    "a test behaviour refused to encode"
)]
#[case::decode(
    CipherBoxError::Decode(DecodeError::UnknownTag { tag: 3 }),
    "the tag 3 names no variant"
)]
#[case::buffer(
    CipherBoxError::Buffer(BufferError::PageNoLongerAvailable),
    "the page is no longer available"
)]
#[case::aead(
    CipherBoxError::Aead(AeadError::Core(AeadCoreError::AuthenticationFailed)),
    "the tag does not match: the ciphertext was changed, or sealed with another key"
)]
#[case::poisoned(
    CipherBoxError::Poisoned,
    "the box is poisoned: an operation failed partway, and the plaintext it had exposed was zeroized"
)]
#[case::zeroized(
    CipherBoxError::Zeroized,
    "the box was zeroized, and holds nothing to open"
)]
#[case::intentional_cipher_box_error(
    CipherBoxError::IntentionalCipherBoxError,
    "a test behaviour refused this operation on the box"
)]
fn test_cipher_box_error_says_what_happened(#[case] error: CipherBoxError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// CipherBoxError: Error::source
// ============================================================================

#[rstest]
#[case::overflow(CipherBoxError::Overflow(overflow_error()))]
#[case::encode(CipherBoxError::Encode(EncodeError::IntentionalEncodeError))]
#[case::decode(CipherBoxError::Decode(DecodeError::UnknownTag { tag: 3 }))]
#[case::buffer(CipherBoxError::Buffer(BufferError::PageNoLongerAvailable))]
#[case::aead(CipherBoxError::Aead(AeadError::Core(AeadCoreError::AuthenticationFailed)))]
#[case::poisoned(CipherBoxError::Poisoned)]
#[case::zeroized(CipherBoxError::Zeroized)]
#[case::intentional_cipher_box_error(CipherBoxError::IntentionalCipherBoxError)]
fn test_cipher_box_error_source_returns_none(#[case] error: CipherBoxError) {
    assert!(error.source().is_none());
}

/// A buffer error is transparent: what a chain walker reaches past it is the
/// buffer's own cause.
#[test]
fn test_cipher_box_error_sources_what_its_buffer_error_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let error = CipherBoxError::Buffer(BufferError::callback_error(Refused(Cause)));

    let source = error.source().ok_or("the buffer error had no cause")?;

    assert_eq!(source.to_string(), "the callback's own cause");

    Ok(())
}

// ============================================================================
// TruncationTooWide
// ============================================================================

#[test]
fn test_truncation_too_wide_says_what_happened() {
    let error = TruncationTooWide { asked: 33 };

    assert_eq!(
        error.to_string(),
        "a master key of 32 bytes cannot be truncated to 33"
    );
    assert!(error.source().is_none());
}
