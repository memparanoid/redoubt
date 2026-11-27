// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error::Error;

use rstest::rstest;

use crate::error::AllockedVecError;

// ============================================================================
// AllockedVecError: Display
// ============================================================================

#[rstest]
#[case::already_sealed(
    AllockedVecError::AlreadySealed,
    "the vector is sealed, and its capacity is fixed"
)]
#[case::overflow(AllockedVecError::Overflow, "the length would be past usize::MAX")]
#[case::capacity_exceeded(
    AllockedVecError::CapacityExceeded,
    "the vector is full: its capacity is sealed"
)]
fn test_allocked_vec_error_says_what_happened(
    #[case] error: AllockedVecError,
    #[case] expected: &str,
) {
    assert_eq!(error.to_string(), expected);
}

// ============================================================================
// AllockedVecError: Error::source
// ============================================================================

#[rstest]
#[case::already_sealed(AllockedVecError::AlreadySealed)]
#[case::overflow(AllockedVecError::Overflow)]
#[case::capacity_exceeded(AllockedVecError::CapacityExceeded)]
fn test_allocked_vec_error_source_returns_none(#[case] error: AllockedVecError) {
    assert!(error.source().is_none());
}
