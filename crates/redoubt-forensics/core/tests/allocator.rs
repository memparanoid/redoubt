// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#![cfg(target_os = "linux")]

use std::alloc::System;

use redoubt_forensics_allocator::ForensicsAllocator;
use redoubt_forensics_core::{Forensics, QUIET, Reason};

mod support;

use support::helpers::alone;
use support::needles::{SECRET, backwards};

#[global_allocator]
static ALLOCATOR: ForensicsAllocator<System> = ForensicsAllocator::new(System);

fn plant() -> Box<[u8; 32]> {
    let mut held = Box::new([0_u8; 32]);

    // Through the probed copy: `core`'s may leave the secret in a register every
    // spiller form writes down.
    //
    // SAFETY: `held` is an allocation of its own, `SECRET.len()` bytes wide.
    unsafe {
        redoubt_mem_core::copy_nonoverlapping(SECRET.as_ptr(), held.as_mut_ptr(), SECRET.len())
    };

    held
}

// ============================================================================
// dealloc
// ============================================================================

#[redoubt_forensics_macros::test]
fn test_a_block_let_go_unwiped_is_found_after_its_size_is_asked_for_again() -> Result<(), Reason> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    drop(plant());

    // With the allocator off, glibc hands the block just let go to this `Box`,
    // and its zeros hide what was there (measured, debug and release).
    let asked_again = core::hint::black_box(Box::new([0_u8; 32]));

    let report = watch.snapshot()?;

    assert!(report.found, "{report}");

    drop(asked_again);

    Ok(())
}

#[redoubt_forensics_macros::test]
fn test_a_block_wiped_before_it_is_let_go_is_not_found() -> Result<(), Reason> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let mut held = plant();

    // Volatile: a wipe right before a drop is a dead store the optimiser removes.
    for byte in held.iter_mut() {
        // SAFETY: a byte of `held`, reached through a unique borrow.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }

    drop(held);

    let asked_again = core::hint::black_box(Box::new([0_u8; 32]));

    let report = watch.snapshot()?;

    assert!(!report.found, "{report}");
    assert!(report.widest <= QUIET, "{report}");

    drop(asked_again);

    Ok(())
}
