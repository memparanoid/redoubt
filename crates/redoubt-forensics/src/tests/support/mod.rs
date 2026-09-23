// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What more than one test file here reads the copy with.

use core::slice;

use crate::window::{COPY, FLOOR, SP};

/// The offsets of the `wide` bytes at `at` that the copy holds set, after
/// asserting they are inside the window at all.
pub(crate) fn set_in_the_copy(at: usize, wide: usize) -> Vec<usize> {
    // SAFETY: `FLOOR` and `COPY` were written by `open` and `SP` by the freeze
    // the caller just ran, all three on the thread reading them.
    let (floor, stood, copy) = unsafe { (FLOOR, SP, COPY) };

    assert!(
        floor <= at && at + wide <= stood,
        "the frame at {at:#x} is not inside the window {floor:#x}-{stood:#x}",
    );

    // SAFETY: the room is as wide as the window, and the frame is inside it with
    // `wide` bytes to spare, as just asserted.
    let frame = unsafe { slice::from_raw_parts(copy.add(at - floor), wide) };

    frame
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte != 0)
        .map(|(where_it_is, _)| where_it_is)
        .collect()
}
