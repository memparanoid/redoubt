// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtArray;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::support::needles::backwards;
use crate::support::{giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// RedoubtArray::drop
// ============================================================================

#[test]
fn test_a_redoubt_array_dropped_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(held));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array dropped");

    Ok(())
}

// ============================================================================
// RedoubtArray: ownership
// ============================================================================

#[test]
fn test_a_redoubt_array_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array given away, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_redoubt_array_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(held));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array given away");

    Ok(())
}

// ============================================================================
// RedoubtArray: Debug
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints the length, and redacts the contents."]
fn test_formatting_a_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes defaults."]
fn test_making_a_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::from_mut_array
// ============================================================================

#[test]
fn test_a_redoubt_array_from_a_mut_array_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let held = capture(|| RedoubtArray::from_mut_array(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array made from an array, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_redoubt_array_from_a_mut_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let held = capture(|| RedoubtArray::from_mut_array(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array made from an array");

    Ok(())
}

// ============================================================================
// RedoubtArray::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_length_of_a_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_whether_a_redoubt_array_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::replace_from_mut_array
// ============================================================================

#[test]
fn test_a_redoubt_array_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        capture(|| held.replace_from_mut_array(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array replaced, and kept");

    // By reference: `[u8; 32]` is `Copy`, and a `black_box` of it by value puts
    // one more copy on the stack.
    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_redoubt_array_replaced_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        capture(|| held.replace_from_mut_array(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array replaced");

    Ok(())
}

// ============================================================================
// RedoubtArray::as_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_array_as_a_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::as_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_array_as_a_mut_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::as_array
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_array_as_an_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray::as_mut_array
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_array_as_a_mut_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray: Default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes defaults."]
fn test_a_default_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray: Deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_dereferencing_a_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtArray: DerefMut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_mutably_dereferencing_a_redoubt_array_leaves_nothing() {
    // Intentionally empty.
}
