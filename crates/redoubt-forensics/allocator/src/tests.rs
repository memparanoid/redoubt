// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::alloc::{GlobalAlloc, Layout};
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::alloc::System;

use crate::{
    FORENSICS_ALLOCATOR_DIRT, FORENSICS_ALLOCATOR_ENABLED, FORENSICS_ALLOCATOR_INSTALLED,
    ForensicsAllocator, enable_forensics_allocator,
};

/// What the spy fills every block it hands out with, so a block the allocator
/// over it wrote on reads differently.
const HANDED: u8 = 0xAB;
/// What a test writes into a block it holds.
const HELD: u8 = 0x5C;
const DIRT: u8 = 0xFF;
const WIDE: usize = 64;

/// `System`, counting every call that reaches it, and refusing to hand out a
/// block once told to.
#[derive(Default)]
struct Spy {
    refuses: AtomicBool,
    allocs: AtomicUsize,
    alloc_zeroeds: AtomicUsize,
    deallocs: AtomicUsize,
    reallocs: AtomicUsize,
}

// SAFETY: every call is forwarded to `System` with the arguments it came with,
// and what is written stays inside the block `System` handed back.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocs.fetch_add(1, Ordering::SeqCst);

        if self.refuses.load(Ordering::SeqCst) {
            return core::ptr::null_mut();
        }

        // SAFETY: the layout is the caller's, which `GlobalAlloc::alloc` asks to
        // be of a size above zero.
        let block = unsafe { System.alloc(layout) };

        if !block.is_null() {
            // SAFETY: `System` handed back a block of `layout.size()` bytes.
            unsafe { core::ptr::write_bytes(block, HANDED, layout.size()) };
        }

        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.alloc_zeroeds.fetch_add(1, Ordering::SeqCst);

        // SAFETY: the layout is the caller's, as in `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        self.deallocs.fetch_add(1, Ordering::SeqCst);

        // SAFETY: `block` came from `System` through `alloc` with this layout.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.reallocs.fetch_add(1, Ordering::SeqCst);

        // SAFETY: the arguments are the caller's, verbatim.
        unsafe { System.realloc(block, layout, new_size) }
    }
}

fn spied() -> ForensicsAllocator<Spy> {
    ForensicsAllocator::new(Spy::default())
}

fn layout(wide: usize) -> Layout {
    Layout::from_size_align(wide, 8)
        .expect("Infallible: 8 is a power of two, and no width here nears isize::MAX")
}

fn alloc(allocator: &ForensicsAllocator<Spy>, wide: usize) -> *mut u8 {
    // SAFETY: every width asked for here is above zero.
    unsafe { allocator.alloc(layout(wide)) }
}

fn alloc_zeroed(allocator: &ForensicsAllocator<Spy>, wide: usize) -> *mut u8 {
    // SAFETY: as in `alloc`.
    unsafe { allocator.alloc_zeroed(layout(wide)) }
}

/// Gives back a block `held` made.
fn dealloc(allocator: &ForensicsAllocator<Spy>, block: *mut u8) {
    // SAFETY: `held` made `block` through this allocator, `WIDE` bytes wide.
    unsafe { allocator.dealloc(block, layout(WIDE)) }
}

/// Resizes a block `held` made.
fn realloc(allocator: &ForensicsAllocator<Spy>, block: *mut u8, new_size: usize) -> *mut u8 {
    // SAFETY: as in `dealloc`, and every size asked for here is above zero.
    unsafe { allocator.realloc(block, layout(WIDE), new_size) }
}

/// A block no test gives back, read `wide` bytes deep.
fn read<'a>(block: *mut u8, wide: usize) -> &'a [u8] {
    assert!(!block.is_null(), "the block to read is null");

    // SAFETY: every block read is at least `wide` bytes, written whole by the
    // spy, the allocator or the test, and alive for the rest of the process:
    // the ones given back are only ever read while the allocator keeps them.
    unsafe { slice::from_raw_parts(block, wide) }
}

fn held(allocator: &ForensicsAllocator<Spy>) -> *mut u8 {
    let block = alloc(allocator, WIDE);

    assert!(
        !block.is_null(),
        "the spy refused a block it was not told to refuse"
    );

    // SAFETY: the spy handed back a block of `WIDE` bytes.
    unsafe { core::ptr::write_bytes(block, HELD, WIDE) };

    block
}

// ============================================================================
// enable_forensics_allocator
// ============================================================================

#[test]
fn test_enable_forensics_allocator_turns_the_allocator_on() {
    assert!(!FORENSICS_ALLOCATOR_ENABLED.load(Ordering::SeqCst));

    enable_forensics_allocator(None);

    assert!(FORENSICS_ALLOCATOR_ENABLED.load(Ordering::SeqCst));
}

#[test]
fn test_enable_forensics_allocator_keeps_no_dirt_when_given_none() {
    *FORENSICS_ALLOCATOR_DIRT.lock() = Some(DIRT);

    enable_forensics_allocator(None);

    assert_eq!(*FORENSICS_ALLOCATOR_DIRT.lock(), None);
}

#[test]
fn test_enable_forensics_allocator_keeps_the_dirt_it_is_given() {
    enable_forensics_allocator(Some(DIRT));

    assert_eq!(*FORENSICS_ALLOCATOR_DIRT.lock(), Some(DIRT));
}

// ============================================================================
// new
// ============================================================================

#[test]
fn test_new_wraps_the_allocator_it_is_given() {
    let allocator = spied();

    let block = alloc(&allocator, WIDE);

    assert!(!block.is_null());
    assert_eq!(allocator.inner().allocs.load(Ordering::SeqCst), 1);
}

// ============================================================================
// alloc
// ============================================================================

#[test]
fn test_alloc_marks_the_allocator_installed() {
    let allocator = spied();

    assert!(!FORENSICS_ALLOCATOR_INSTALLED.load(Ordering::SeqCst));

    alloc(&allocator, WIDE);

    assert!(FORENSICS_ALLOCATOR_INSTALLED.load(Ordering::SeqCst));
}

#[test]
fn test_alloc_returns_null_when_the_inner_allocator_refuses() {
    let allocator = spied();

    enable_forensics_allocator(Some(DIRT));
    allocator.inner().refuses.store(true, Ordering::SeqCst);

    assert!(alloc(&allocator, WIDE).is_null());
}

#[test]
fn test_alloc_leaves_the_block_as_handed_while_disabled() {
    let allocator = spied();

    *FORENSICS_ALLOCATOR_DIRT.lock() = Some(DIRT);

    let block = alloc(&allocator, WIDE);

    assert!(read(block, WIDE).iter().all(|&byte| byte == HANDED));
}

#[test]
fn test_alloc_leaves_the_block_as_handed_while_enabled_without_dirt() {
    let allocator = spied();

    enable_forensics_allocator(None);

    let block = alloc(&allocator, WIDE);

    assert!(read(block, WIDE).iter().all(|&byte| byte == HANDED));
}

#[test]
fn test_alloc_dirties_the_block_while_enabled_with_dirt() {
    let allocator = spied();

    enable_forensics_allocator(Some(DIRT));

    let block = alloc(&allocator, WIDE);

    assert!(read(block, WIDE).iter().all(|&byte| byte == DIRT));
}

// ============================================================================
// alloc_zeroed
// ============================================================================

#[test]
fn test_alloc_zeroed_marks_the_allocator_installed() {
    let allocator = spied();

    assert!(!FORENSICS_ALLOCATOR_INSTALLED.load(Ordering::SeqCst));

    alloc_zeroed(&allocator, WIDE);

    assert!(FORENSICS_ALLOCATOR_INSTALLED.load(Ordering::SeqCst));
}

#[test]
fn test_alloc_zeroed_hands_zeroes_from_the_inner_allocator_while_enabled_with_dirt() {
    let allocator = spied();

    enable_forensics_allocator(Some(DIRT));

    let block = alloc_zeroed(&allocator, WIDE);

    assert_eq!(allocator.inner().alloc_zeroeds.load(Ordering::SeqCst), 1);
    assert_eq!(allocator.inner().allocs.load(Ordering::SeqCst), 0);
    assert!(read(block, WIDE).iter().all(|&byte| byte == 0));
}

// ============================================================================
// dealloc
// ============================================================================

#[test]
fn test_dealloc_frees_through_the_inner_allocator_while_disabled() {
    let allocator = spied();
    let block = held(&allocator);

    dealloc(&allocator, block);

    assert_eq!(allocator.inner().deallocs.load(Ordering::SeqCst), 1);
}

#[test]
fn test_dealloc_frees_nothing_while_enabled() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(None);

    dealloc(&allocator, block);

    assert_eq!(allocator.inner().deallocs.load(Ordering::SeqCst), 0);
    assert!(read(block, WIDE).iter().all(|&byte| byte == HELD));
}

// ============================================================================
// realloc
// ============================================================================

#[test]
fn test_realloc_goes_through_the_inner_realloc_while_disabled() {
    let allocator = spied();
    let block = held(&allocator);

    let grown = realloc(&allocator, block, 2 * WIDE);

    assert_eq!(allocator.inner().reallocs.load(Ordering::SeqCst), 1);
    assert_eq!(allocator.inner().allocs.load(Ordering::SeqCst), 1);
    assert_eq!(allocator.inner().deallocs.load(Ordering::SeqCst), 0);
    assert!(read(grown, WIDE).iter().all(|&byte| byte == HELD));
}

#[test]
fn test_realloc_returns_null_while_enabled_when_the_inner_allocator_refuses() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(None);
    allocator.inner().refuses.store(true, Ordering::SeqCst);

    assert!(realloc(&allocator, block, 2 * WIDE).is_null());
    assert!(read(block, WIDE).iter().all(|&byte| byte == HELD));
}

#[test]
fn test_realloc_allocates_anew_and_frees_nothing_while_enabled() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(None);

    realloc(&allocator, block, 2 * WIDE);

    assert_eq!(allocator.inner().reallocs.load(Ordering::SeqCst), 0);
    assert_eq!(allocator.inner().allocs.load(Ordering::SeqCst), 2);
    assert_eq!(allocator.inner().deallocs.load(Ordering::SeqCst), 0);
}

#[test]
fn test_realloc_leaves_the_old_block_as_it_was_while_enabled() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(Some(DIRT));

    let grown = realloc(&allocator, block, 2 * WIDE);

    assert_ne!(grown, block);
    assert!(read(block, WIDE).iter().all(|&byte| byte == HELD));
}

#[test]
fn test_realloc_carries_what_was_held_while_enabled() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(None);

    let grown = realloc(&allocator, block, 2 * WIDE);
    let (carried, beyond) = read(grown, 2 * WIDE).split_at(WIDE);

    assert!(carried.iter().all(|&byte| byte == HELD));
    assert!(beyond.iter().all(|&byte| byte == HANDED));
}

#[test]
fn test_realloc_dirties_what_it_grows_into_while_enabled_with_dirt() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(Some(DIRT));

    let grown = realloc(&allocator, block, 2 * WIDE);
    let (carried, beyond) = read(grown, 2 * WIDE).split_at(WIDE);

    assert!(carried.iter().all(|&byte| byte == HELD));
    assert!(beyond.iter().all(|&byte| byte == DIRT));
}

#[test]
fn test_realloc_carries_only_what_fits_when_it_shrinks_while_enabled() {
    let allocator = spied();
    let block = held(&allocator);

    enable_forensics_allocator(Some(DIRT));

    let shrunk = realloc(&allocator, block, WIDE / 2);

    assert!(read(shrunk, WIDE / 2).iter().all(|&byte| byte == HELD));
}
