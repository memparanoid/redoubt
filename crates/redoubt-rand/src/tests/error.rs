// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::error::Error;
use std::string::ToString;

use rstest::rstest;

use crate::error::EntropyError;

// ============================================================================
// EntropyError: Display
// ============================================================================

#[rstest]
#[case::entropy_not_available(EntropyError::EntropyNotAvailable, "the system gave no entropy")]
#[case::injected(EntropyError::Injected, "a test behaviour refused to give entropy")]
fn test_entropy_error_says_what_happened(#[case] error: EntropyError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// EntropyError: Error::source
// ============================================================================

#[rstest]
#[case::entropy_not_available(EntropyError::EntropyNotAvailable)]
#[case::injected(EntropyError::Injected)]
fn test_entropy_error_source_returns_none(#[case] error: EntropyError) {
    assert!(error.source().is_none());
}
