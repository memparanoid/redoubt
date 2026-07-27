// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! An allocator that never reuses memory, so that absence means something.
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: NeverFree = NeverFree;
//! ```
//!
//! ## The problem it solves
//!
//! A forensic run answers "is this secret still in memory". Without this
//! allocator it cannot, because two very different situations produce the same
//! empty result:
//!
//! - the value was zeroized, so there is nothing to find, **or**
//! - the value leaked into a freed block, and a later allocation happened to be
//!   served out of that same block and overwrote it before the dump ran
//!
//! The second case is not a corner case. Measured on this lab: the same binary,
//! changing only the *length of the dump file's path*, went from finding a
//! 79-byte plaintext residue in 10 runs out of 10 to finding it in 0 out of 10.
//! The leak was identical in both. What changed was where the allocator placed
//! everything afterwards, and therefore whether something landed on top of the
//! evidence.
//!
//! That makes a clean report worthless on its own, and comparisons actively
//! misleading: two builds that differ by a single `assert!` allocate
//! differently, so one can report a leak and the other silence while both
//! contain exactly the same bug.
//!
//! ## What it does
//!
//! `alloc` delegates to the system allocator unchanged — same sizes, same
//! alignment, no extra memory per request. `dealloc` does nothing, so a freed
//! block never returns to the free list and can never be handed out again.
//!
//! Every allocation therefore gets untouched memory, and everything ever freed
//! stays exactly as it was left. Nothing can overwrite the evidence, so an
//! absent value really is absent, and two runs of different builds become
//! comparable.
//!
//! `realloc` comes along for free. The default implementation allocates, copies
//! and frees, so with a no-op `dealloc` every intermediate buffer of a growing
//! collection stays visible — which is precisely where a container that
//! zeroizes on drop can still leak, since the copies left behind by growth were
//! never anybody's to drop.
//!
//! ## What it does not cover
//!
//! **The stack.** Frames are overwritten by ordinary calls, and no allocator has
//! any say in that. A copy the optimizer spilled to the stack remains as
//! intermittent as it was.
//!
//! **Allocations that bypass Rust's global allocator**, such as a C dependency
//! calling `malloc` directly.
//!
//! ## Cost
//!
//! Peak memory becomes total memory: a program that allocates and frees the
//! same buffer a thousand times now holds a thousand buffers. For a forensic
//! run that is a few megabytes, and the dump grows to match.
//!
//! ## Not for production
//!
//! This is a measuring instrument. Any long-running process using it grows
//! without bound.

use core::alloc::{GlobalAlloc, Layout};
use std::alloc::System;

/// A [`GlobalAlloc`] that allocates normally and never frees.
///
/// See the module documentation for why a forensic build needs one.
pub struct NeverFree;

unsafe impl GlobalAlloc for NeverFree {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    /// Deliberately empty.
    ///
    /// Returning the block would let a later allocation be served out of it,
    /// overwriting whatever the freed value left behind — which is the evidence
    /// the run exists to collect.
    #[inline]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    // `realloc` is intentionally left as the default: allocate, copy, free.
    // With `dealloc` doing nothing, that keeps every intermediate buffer of a
    // growing collection intact and visible in the dump.
}
