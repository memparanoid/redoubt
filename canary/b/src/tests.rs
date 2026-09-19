// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::quarter_of_four;

// === === === === === === === === === ===
// quarter_of_four
// === === === === === === === === === ===

#[test]
fn test_quarter_of_four_answers_one() {
    assert_eq!(quarter_of_four(), Ok(1));
}
