// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::is_utf8;

// ============================================================================
// is_utf8
// ============================================================================

#[test]
fn test_is_utf8_resolves_the_default_backend() {
    assert!(is_utf8("a\u{e9}\u{20ac}\u{1f600}".as_bytes()));
    assert!(!is_utf8(&[0xC0, 0x80]));
}
