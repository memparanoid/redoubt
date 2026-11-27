// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error::Error;

use crate::error::HkdfError;

// ============================================================================
// HkdfError
// ============================================================================

#[test]
fn test_hkdf_error_says_what_happened() {
    assert_eq!(
        HkdfError::OutputTooLong.to_string(),
        "more output was asked for than the 8160 bytes a derivation gives"
    );
}

#[test]
fn test_hkdf_error_source_returns_none() {
    assert!(HkdfError::OutputTooLong.source().is_none());
}
