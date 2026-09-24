// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtArray;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::support::needles::backwards;
use crate::support::{giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// RedoubtArray::replace_from_mut_array
// ============================================================================

/// What the array was filled from is found while the array holds it.
///
/// An array's size is in its type, so there is no sweep over sizes to make
/// here and one is the whole of it.
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

    // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of it by
    // value makes one more copy on the stack, and the test would be measuring
    // itself.
    core::hint::black_box(&source);

    Ok(())
}

/// Once the array is let go, nothing of it is anywhere.
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
        // below is about that call and not about the operation. See the header.
        drop(held);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array replaced");

    Ok(())
}

// ============================================================================
// RedoubtArray: ownership
// ============================================================================

/// An array given away is found while whoever took it is holding it.
///
/// This is the pair that says what `RedoubtArray` is. It reads as a value that
/// would carry its bytes with it and does not: it holds a `Box<[T; N]>`, so a
/// move moves a pointer and the bytes stay where they were put. Take the `Box`
/// away and the test below starts finding the secret in the slot the value was
/// moved out of, with nobody left to empty it.
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

/// Once whoever took it lets it go, nothing is left where it was.
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
// RedoubtArray::drop
// ============================================================================

/// One that is dropped leaves nothing.
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
