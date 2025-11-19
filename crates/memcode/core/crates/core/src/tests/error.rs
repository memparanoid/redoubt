// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::OverflowError;

#[test]
fn test_overflow_error() {
    let error = OverflowError {
        reason: "Custom Overflow Error".into(),
    };
    let dbg_1 = format!("{:?}", error);
    let dbg_2 = format!("{}", error);

    assert_eq!(dbg_1, "OverflowError { reason: \"Custom Overflow Error\" }");
    assert_eq!(dbg_2, "Overflow Error");
}
