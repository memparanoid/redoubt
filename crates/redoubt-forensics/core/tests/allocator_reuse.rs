// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicPtr, Ordering};

use redoubt_forensics_core::{
    Forensics, ForensicsAllocator, QUIET, Reason, enable_forensics_allocator,
};

mod support;

use support::helpers::alone;
use support::needles::{SECRET, backwards};

/// A size nothing but these tests asks for, so the harness never lands a block
/// of its own in the slot between a drop and the next request.
const ONLY_THIS_TEST_ASKS: usize = 777;

/// `System`, except that the last block of `ONLY_THIS_TEST_ASKS` bytes let go
/// is handed out again, zeroed, to the next request of that size: the reuse
/// every allocator makes, made certain.
struct Reusing {
    slot: AtomicPtr<u8>,
}

impl Reusing {
    const fn new() -> Self {
        Self {
            slot: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

// SAFETY: a block handed out again is one `System` made at that size, and only
// ever asked for with the alignment of a `Vec<u8>`; every other call reaches
// `System` with the arguments it came with.
unsafe impl GlobalAlloc for Reusing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == ONLY_THIS_TEST_ASKS {
            let kept = self.slot.swap(core::ptr::null_mut(), Ordering::SeqCst);

            if !kept.is_null() {
                // SAFETY: `kept` is a block of `ONLY_THIS_TEST_ASKS` bytes that
                // left the slot here, so nothing else holds it.
                unsafe { core::ptr::write_bytes(kept, 0, ONLY_THIS_TEST_ASKS) };

                return kept;
            }
        }

        // SAFETY: the layout is the caller's, which `GlobalAlloc::alloc` asks to
        // be of a size above zero.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if layout.size() == ONLY_THIS_TEST_ASKS {
            let kept = self.slot.swap(block, Ordering::SeqCst);

            if !kept.is_null() {
                // SAFETY: `kept` came from `System` at this size and alignment.
                unsafe { System.dealloc(kept, layout) };
            }

            return;
        }

        // SAFETY: `block` came from `System` with this layout.
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ForensicsAllocator<Reusing> = ForensicsAllocator::new(Reusing::new());

fn plant() -> Vec<u8> {
    let mut held = Vec::with_capacity(ONLY_THIS_TEST_ASKS);

    // Through the probed copy: `core`'s may leave the secret in a register every
    // spiller form writes down.
    //
    // SAFETY: `held` is an allocation of its own with room for `SECRET.len()`
    // bytes, all of them written before the length says so.
    unsafe {
        redoubt_mem_core::copy_nonoverlapping(SECRET.as_ptr(), held.as_mut_ptr(), SECRET.len());
        held.set_len(SECRET.len());
    }

    held
}

// ============================================================================
// dealloc
// ============================================================================

#[test]
fn test_a_vec_let_go_unwiped_is_not_found_once_its_block_is_handed_out_again_while_disabled()
-> Result<(), Reason> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let held = plant();
    let at = held.as_ptr();

    drop(held);

    let asked_again = core::hint::black_box(Vec::<u8>::with_capacity(ONLY_THIS_TEST_ASKS));

    assert_eq!(asked_again.as_ptr(), at);

    let report = watch.snapshot()?;

    assert!(!report.found, "{report}");

    drop(asked_again);

    Ok(())
}

#[test]
fn test_a_vec_let_go_unwiped_is_found_while_enabled_although_its_size_is_asked_for_again()
-> Result<(), Reason> {
    alone!();

    enable_forensics_allocator(None);

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let held = plant();
    let at = held.as_ptr();

    drop(held);

    let asked_again = core::hint::black_box(Vec::<u8>::with_capacity(ONLY_THIS_TEST_ASKS));

    assert_ne!(asked_again.as_ptr(), at);

    let report = watch.snapshot()?;

    assert!(report.found, "{report}");

    drop(asked_again);

    Ok(())
}

#[test]
fn test_a_vec_wiped_before_it_is_let_go_is_not_found_while_enabled() -> Result<(), Reason> {
    alone!();

    enable_forensics_allocator(None);

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let mut held = plant();

    // Volatile: a wipe right before a drop is a dead store the optimiser removes.
    for byte in held.iter_mut() {
        // SAFETY: a byte of `held`, reached through a unique borrow.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }

    drop(held);

    let asked_again = core::hint::black_box(Vec::<u8>::with_capacity(ONLY_THIS_TEST_ASKS));

    let report = watch.snapshot()?;

    assert!(!report.found, "{report}");
    assert!(report.widest <= QUIET, "{report}");

    drop(asked_again);

    Ok(())
}
