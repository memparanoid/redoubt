// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That what the compiler folds into a captured operation ends up in the
//! window, byte for byte.
//!
//! # A process each
//!
//! There is one window in a process, so a second `open` replaces the first and
//! a second freeze writes over it. `nextest`, not `cargo test`.

use crate::errors::Reason;
use crate::frame::capture;
use crate::freeze;
use crate::window::{SP, open};

use super::support::set_in_the_copy;

/// How wide the frames here are.
const WIDE: usize = 256;

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

// ============================================================================
// capture
// ============================================================================

/// An operation the compiler inlines keeps its locals in whatever frame it was
/// inlined into, and here that frame is the one `capture` runs it in.
#[test]
fn test_every_byte_of_a_frame_an_inlined_capture_left_is_in_the_copy_at_its_own_offset()
-> Result<(), Reason> {
    open()?;

    for offset in 0..WIDE {
        let at = capture(|| a_frame_with_one_byte_set(offset));

        assert_eq!(
            set_in_the_copy(at, WIDE),
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
