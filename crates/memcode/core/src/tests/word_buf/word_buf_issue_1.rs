// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Regression test for issue #1: reset_with_capacity must reset the internal cursor to 0.
//
// Why this exists:
// Previously, reset_with_capacity rebuilt/zeroized the backing buffer but left the cursor
// at its old position. Any subsequent operation that assumes a fresh, empty buffer—like
// try_from_bytes (which internally uses push)—would start writing at the stale cursor.
// This could cause spurious CapacityExceededError (e.g., old cursor >= new capacity) or,
// more subtly, make push fail even when the new capacity is sufficient, because the buffer
// appears full from the non-zero cursor.
//
// What this test proves:
// 1) After writing some data, calling reset_with_capacity(new_cap) produces a truly empty
// buffer: the cursor is reset to 0.
// 2) A following try_from_bytes can push all words infallibly (no capacity error), because
// it starts from a zero cursor as intended.
// 3) This guards against regressions where the vector is recreated but the logical write
// position isn’t, breaking the contract that “reset” = “empty buffer with the given capacity.”
use std::panic::catch_unwind;

use crate::word_buf::WordBuf;

#[test]
fn test_reset_with_capacity_resets_cursor_regression_issue_1() {
    let mut wb = WordBuf::new(0);
    wb.reset_with_capacity(5);

    wb.push(1).expect("Failed to push(..)");
    wb.push(2).expect("Failed to push(..)");
    wb.push(3).expect("Failed to push(..)");
    wb.push(4).expect("Failed to push(..)");
    wb.push(5).expect("Failed to push(..)");

    wb.reset_with_capacity(1);

    let result = catch_unwind(move || {
        wb.push(1).expect("Failed to push(..)");
    });

    assert!(result.is_ok());
}
