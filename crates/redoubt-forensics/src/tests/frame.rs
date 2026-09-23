// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That what a capture runs ends up in the window, byte for byte.
//!
//! # A process each
//!
//! There is one window in a process, so a second `open` replaces the first and
//! a second freeze writes over it. `nextest`, not `cargo test`.

use core::slice;

use crate::errors::Reason;
use crate::frame::capture;
use crate::freeze;
use crate::window::{COPY, FLOOR, SP, open};

/// How wide the frames here are, which the assembly's is too.
const WIDE: usize = 256;

unsafe extern "C" {
    /// A frame of [`WIDE`] zeroes with a one at `at`, released before it
    /// answers, and where it stood.
    fn redoubt_dirty_frame(at: usize) -> *const u8;
}

/// A frame of [`WIDE`] zeroes with a one at `at`, laid out by the compiler in
/// whatever frame it is inlined into, and where it stood.
///
/// Always inlined, because that is the case under test: code folded into its
/// caller, whose locals are that caller's.
#[inline(always)]
fn a_frame_with_one_byte_set(at: usize) -> usize {
    let mut room = [0_u8; WIDE];

    // SAFETY: every caller passes an offset below `WIDE`.
    unsafe { room.as_mut_ptr().add(at).write_volatile(1) };

    core::hint::black_box(&mut room).as_ptr() as usize
}

/// `capture` with the frame of its own taken away: the operation folded into
/// whoever called it.
#[inline(always)]
fn capture_inlined<R>(operation: impl FnOnce() -> R) -> R {
    let out = operation();

    freeze!();

    out
}

/// The offsets of the frame at `at` that the copy holds set, after asserting the
/// frame is inside the window at all.
fn set_in_the_copy(at: usize) -> Vec<usize> {
    // SAFETY: `FLOOR` and `COPY` were written by `open` and `SP` by the freeze
    // the caller just ran, all three on the thread reading them.
    let (floor, stood, copy) = unsafe { (FLOOR, SP, COPY) };

    assert!(
        floor <= at && at + WIDE <= stood,
        "the frame at {at:#x} is not inside the window {floor:#x}-{stood:#x}",
    );

    // SAFETY: the room is as wide as the window, and the frame is inside it with
    // `WIDE` bytes to spare, as just asserted.
    let frame = unsafe { slice::from_raw_parts(copy.add(at - floor), WIDE) };

    frame
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte != 0)
        .map(|(where_it_is, _)| where_it_is)
        .collect()
}

// ============================================================================
// capture
// ============================================================================

/// The frame the assembly leaves sits under one more here, the one `capture`
/// runs the operation in.
#[test]
fn test_every_byte_of_a_frame_a_captured_call_left_is_in_the_copy_at_its_own_offset()
-> Result<(), Reason> {
    open()?;

    for offset in 0..WIDE {
        // SAFETY: the offset is inside the frame the routine takes, and the
        // address it answers with is read only through the copy.
        let at = capture(|| unsafe { redoubt_dirty_frame(offset) }) as usize;

        assert_eq!(
            set_in_the_copy(at),
            [offset],
            "the frame left with byte {offset} set came back with these set",
        );
    }

    Ok(())
}

/// An operation the compiler inlines keeps its locals in whatever frame it was
/// inlined into, and here that frame is the one `capture` runs it in.
#[test]
fn test_every_byte_of_a_frame_an_inlined_capture_left_is_in_the_copy_at_its_own_offset()
-> Result<(), Reason> {
    open()?;

    for offset in 0..WIDE {
        let at = capture(|| a_frame_with_one_byte_set(offset));

        assert_eq!(
            set_in_the_copy(at),
            [offset],
            "the inlined frame left with byte {offset} set came back with these set",
        );
    }

    Ok(())
}

/// Folded into the caller, the frame `capture` would have run the operation in
/// is the caller's, above the stack pointer the freeze ran at, where the copy
/// never reaches.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "Unoptimized, a closure is a call with a frame of its own, so nothing \
              is folded into the caller and there is no hazard here to show."
)]
fn test_a_frame_left_without_a_frame_of_its_own_is_outside_the_window() -> Result<(), Reason> {
    open()?;

    let at = capture_inlined(|| a_frame_with_one_byte_set(0));

    // SAFETY: written by the freeze just above, on the thread reading it.
    let stood = unsafe { SP };

    assert!(
        at >= stood,
        "the frame at {at:#x} is below the stack pointer {stood:#x} the freeze \
         ran at, so inlining did not put it in the caller's frame",
    );

    Ok(())
}
