// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error::Error;

use rstest::rstest;

use crate::error::{
    DecodeBufferError, DecodeError, EncodeError, OverflowError, RedoubtCodecBufferError,
};

fn overflow_error() -> OverflowError {
    OverflowError {
        reason: "Custom Overflow Error".into(),
    }
}

// ============================================================================
// OverflowError
// ============================================================================

#[test]
fn test_overflow_error() {
    let error = overflow_error();
    let dbg_1 = format!("{:?}", error);
    let dbg_2 = format!("{}", error);

    assert_eq!(dbg_1, "OverflowError { reason: \"Custom Overflow Error\" }");
    assert_eq!(
        dbg_2,
        "the encoded size would be past usize::MAX: Custom Overflow Error"
    );
}

#[test]
fn test_overflow_error_source_returns_none() {
    assert!(overflow_error().source().is_none());
}

// ============================================================================
// RedoubtCodecBufferError
// ============================================================================

#[test]
fn test_redoubt_codec_buffer_error_says_what_happened() {
    let error = RedoubtCodecBufferError::CapacityExceeded;

    assert_eq!(
        error.to_string(),
        "the buffer is full: what is written does not fit its capacity"
    );
    assert!(error.source().is_none());
}

// ============================================================================
// DecodeBufferError
// ============================================================================

#[test]
fn test_decode_buffer_error_says_what_happened() {
    let error = DecodeBufferError::OutOfBounds;

    assert_eq!(
        error.to_string(),
        "the bytes end before what is read from them"
    );
    assert!(error.source().is_none());
}

// ============================================================================
// EncodeError
// ============================================================================

#[rstest]
#[case::overflow_error(
    EncodeError::OverflowError(overflow_error()),
    "the encoded size would be past usize::MAX: Custom Overflow Error"
)]
#[case::redoubt_codec_buffer_error(
    EncodeError::RedoubtCodecBufferError(RedoubtCodecBufferError::CapacityExceeded),
    "the buffer is full: what is written does not fit its capacity"
)]
#[case::intentional_encode_error(
    EncodeError::IntentionalEncodeError,
    "a test behaviour refused to encode"
)]
fn test_encode_error_says_what_happened(#[case] error: EncodeError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
    assert!(error.source().is_none());
}

// ============================================================================
// DecodeError
// ============================================================================

#[rstest]
#[case::decode_buffer_error(
    DecodeError::DecodeBufferError(DecodeBufferError::OutOfBounds),
    "the bytes end before what is read from them"
)]
#[case::precondition_violated(
    DecodeError::PreconditionViolated,
    "the bytes are not an encoding of what is decoded into"
)]
#[case::unknown_tag(DecodeError::UnknownTag { tag: 7 }, "the tag 7 names no variant")]
#[case::intentional_decode_error(
    DecodeError::IntentionalDecodeError,
    "a test behaviour refused to decode"
)]
fn test_decode_error_says_what_happened(#[case] error: DecodeError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
    assert!(error.source().is_none());
}
