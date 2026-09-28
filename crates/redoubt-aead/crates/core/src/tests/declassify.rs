// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::declassify;

// ============================================================================
// declassify
// ============================================================================

#[test]
fn test_declassify_returns_true_as_it_was() {
    assert!(declassify(true));
}

#[test]
fn test_declassify_returns_false_as_it_was() {
    assert!(!declassify(false));
}
