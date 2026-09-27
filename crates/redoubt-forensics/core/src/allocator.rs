// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The global allocator a forensics test runs under.
//!
//! # What it keeps that the system's does not
//!
//! Measured with glibc, debug and release: a block let go unwiped and then
//! asked for again at the same size is not found once the new owner writes
//! over it, because the system hands the same block back. Enabled, this gives
//! nothing back, and the same block is found.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};

use quiesce::Mutex;

/// Whether a [`ForensicsAllocator`] has handed out a block in this process.
pub(crate) static FORENSICS_ALLOCATOR_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether blocks are kept rather than given back.
pub(crate) static FORENSICS_ALLOCATOR_ENABLED: AtomicBool = AtomicBool::new(false);

/// The byte every block handed out while enabled is filled with, if any.
pub(crate) static FORENSICS_ALLOCATOR_DIRT: Mutex<Option<u8>> = Mutex::new(None);

/// Turns the allocator on for the rest of the process, filling what it hands
/// out with `dirt` when there is one.
#[doc(hidden)]
pub fn enable_forensics_allocator(dirt: Option<u8>) {
    // The dirt first: an allocation that sees the allocator on reads it.
    *FORENSICS_ALLOCATOR_DIRT.lock() = dirt;

    FORENSICS_ALLOCATOR_ENABLED.store(true, Ordering::SeqCst);
}

/// A [`GlobalAlloc`] over `A`. Off, every call reaches `A` as it came; on,
/// nothing is given back to `A`, so a block let go keeps what it held.
pub struct ForensicsAllocator<A> {
    inner: A,
}

impl<A> ForensicsAllocator<A> {
    /// The allocator over `inner`, off until a test turns it on.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &A {
        &self.inner
    }
}

// SAFETY: every block handed out is one `A` made with the layout the caller
// holds it under, and every block given back reaches `A` with that layout. A
// block kept is leaked, which is sound.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ForensicsAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        FORENSICS_ALLOCATOR_INSTALLED.store(true, Ordering::Relaxed);

        // SAFETY: the layout is the caller's, which `GlobalAlloc::alloc` asks to
        // be of a size above zero.
        let block = unsafe { self.inner.alloc(layout) };

        if block.is_null() || !FORENSICS_ALLOCATOR_ENABLED.load(Ordering::SeqCst) {
            return block;
        }

        if let Some(dirt) = *FORENSICS_ALLOCATOR_DIRT.lock() {
            // SAFETY: `A` handed back a block of `layout.size()` bytes.
            unsafe { core::ptr::write_bytes(block, dirt, layout.size()) };
        }

        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        FORENSICS_ALLOCATOR_INSTALLED.store(true, Ordering::Relaxed);

        // SAFETY: the layout is the caller's, as in `alloc`.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if FORENSICS_ALLOCATOR_ENABLED.load(Ordering::SeqCst) {
            return;
        }

        // SAFETY: `block` came from this allocator with `layout`, and every block
        // this hands out is `A`'s.
        unsafe { self.inner.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !FORENSICS_ALLOCATOR_ENABLED.load(Ordering::SeqCst) {
            // SAFETY: the arguments are the caller's, verbatim.
            return unsafe { self.inner.realloc(block, layout, new_size) };
        }

        // `A::realloc` would give the old block back inside itself when it moves
        // it, past `dealloc`.
        //
        // SAFETY: `GlobalAlloc::realloc` asks `new_size` to be above zero and not
        // to overflow `isize` once rounded up to the alignment, which is what a
        // `Layout` asks.
        let grown_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };

        // SAFETY: a layout of a size above zero, as above.
        let grown = unsafe { self.alloc(grown_layout) };

        if !grown.is_null() {
            // `core::ptr::copy_nonoverlapping` would be libc's `memcpy` at a length
            // the compiler does not know, which leaves what it copied in the
            // vector registers.
            //
            // SAFETY: each block holds at least `layout.size().min(new_size)`
            // bytes, and a block just handed out overlaps none still held.
            unsafe {
                redoubt_mem_core::copy_nonoverlapping(block, grown, layout.size().min(new_size))
            };
        }

        grown
    }
}
