// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # Why each `T` is its own set of sections
//!
//! `ZeroizingGuard::from_mut` is a `mem::swap` between the caller's value and a
//! freshly boxed default, and what that swap moves depends entirely on `T`.
//!
//! A `Vec<u8>` is a pointer, a length and a capacity: the swap moves
//! twenty-four bytes of header and the secret never leaves the heap block it
//! was already in. An inline `[u8; 32]` has no header — the swap moves the
//! secret itself, through whatever the compiler picked to move it with. Four
//! kilobytes inline is a third question again: at that size the move is a call
//! into the C library with the secret as its argument.
//!
//! Those are three different questions with one name on them, and a single test
//! answering all three would say which only by accident.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero_core::ZeroizingGuard;

use crate::support::needles::{SECRET, backwards};
use crate::support::{Wide, giving, is_found, leaves_nothing, let_go};

// ============================================================================
// ZeroizingGuard<Vec<u8>>::from_mut
// ============================================================================

#[test]
fn test_a_guarded_vec_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec guarded, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// Taking a vec of one size, and letting the guard go.
macro_rules! a_guarded_vec {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the swap left, and then the
                // absence below is about that call and not about the swap.
                drop(guard);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes guarded", $of),
            );

            Ok(())
        }
    };
}

a_guarded_vec!(test_guarding_a_vec_of_32_leaves_nothing, 32);
a_guarded_vec!(test_guarding_a_vec_of_64_leaves_nothing, 64);
a_guarded_vec!(test_guarding_a_vec_of_128_leaves_nothing, 128);
a_guarded_vec!(test_guarding_a_vec_of_512_leaves_nothing, 512);
a_guarded_vec!(test_guarding_a_vec_of_1024_leaves_nothing, 1024);
a_guarded_vec!(test_guarding_a_vec_of_4096_leaves_nothing, 4096);
a_guarded_vec!(test_guarding_a_vec_of_16384_leaves_nothing, 16384);
a_guarded_vec!(test_guarding_a_vec_of_65536_leaves_nothing, 65536);

// ============================================================================
// ZeroizingGuard<Vec<u8>>: ownership
// ============================================================================

#[test]
fn test_a_guarded_vec_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether the move itself leaves a copy in the
        // registers or the stack it used.
        capture(|| let_go(guard));
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec given away");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Vec<u8>>::drop
// ============================================================================

#[test]
fn test_dropping_a_guarded_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is what the drop itself leaves in the registers
        // or the stack it used.
        capture(|| drop(guard));
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec dropped");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>::from_mut
// ============================================================================

/// The shape that caught `RedoubtArray`: a swap of an inline array moves the
/// bytes rather than a pointer to them, and what it moves them through is
/// nobody's to choose.
#[test]
fn test_a_guarded_array_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array guarded, and kept");

    // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of it by
    // value makes one more copy on the stack, and the test would be measuring
    // itself.
    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_guarding_an_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the swap left, and then the absence
        // below is about that call and not about the swap.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array guarded");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>: ownership
// ============================================================================

#[test]
fn test_a_guarded_array_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation.
        capture(|| let_go(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array given away");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>::drop
// ============================================================================

#[test]
fn test_dropping_a_guarded_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array dropped");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>::from_mut
// ============================================================================

/// The one the thirty-two byte section cannot reach: at that size a `mem::swap`
/// is a few loads and stores, and at this one it is a call into the C library
/// with the secret as its argument.
#[test]
fn test_a_guarded_wide_value_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes guarded, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_guarding_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the swap left, and then the absence
        // below is about that call and not about the swap.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes guarded");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>: ownership
// ============================================================================

#[test]
fn test_a_guarded_wide_value_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation.
        capture(|| let_go(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes given away");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>::drop
// ============================================================================

#[test]
fn test_dropping_a_guarded_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes dropped");

    Ok(())
}
