// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::error::Error;
use std::string::ToString;

use rstest::rstest;

use crate::error::HexError;

// ============================================================================
// HexError: Display
// ============================================================================

#[rstest]
#[case::odd_length(
    HexError::OddLength,
    "an odd number of hex digits spells no whole byte"
)]
#[case::wrong_destination(
    HexError::WrongDestination,
    "the destination is not as long as what is written into it"
)]
#[case::not_hex(HexError::NotHex, "a character is not a hex digit")]
fn test_hex_error_says_what_happened(#[case] error: HexError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// HexError: Error::source
// ============================================================================

#[rstest]
#[case::odd_length(HexError::OddLength)]
#[case::wrong_destination(HexError::WrongDestination)]
#[case::not_hex(HexError::NotHex)]
fn test_hex_error_source_returns_none(#[case] error: HexError) {
    assert!(error.source().is_none());
}
