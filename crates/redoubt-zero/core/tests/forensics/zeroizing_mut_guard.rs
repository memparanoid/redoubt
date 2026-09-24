// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # And why the borrowing guard is measured at all
//!
//! `ZeroizingMutGuard` holds a `&mut T` and never moves the value: the secret
//! stays in the caller's own variable and is zeroized there. So there should be
//! nothing for a move to leave anywhere.
//!
//! It is worth pinning even so. The difference between the two guards is one
//! word in a struct field, and a future `from` that took `T` by value would
//! read almost the same and leak exactly like the other one did.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero_core::ZeroizingMutGuard;

use crate::support::needles::{SECRET, backwards};
use crate::support::{Wide, giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// ZeroizingMutGuard<Vec<u8>>
// ============================================================================

/// What the guard borrowed is found while the guard holds it.
///
/// Where it is found is the caller's own variable, because that is the one
/// place a borrowing guard ever puts anything.
#[test]
fn test_a_borrowed_vec_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingMutGuard::from(&mut source));

        hold_on(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec borrowed, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// Borrowing a vec of one size, and letting the guard go.
macro_rules! a_borrowed_vec {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let guard = ZeroizingMutGuard::from(&mut source);

                // CORRECTNESS: inside the capture, because the drop is the
                // operation. A borrowing guard moves nothing on the way in —
                // what it does is wipe the caller's value on the way out.
                capture(|| drop(guard));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes borrowed", $of),
            );

            Ok(())
        }
    };
}

a_borrowed_vec!(test_borrowing_a_vec_of_32_leaves_nothing, 32);
a_borrowed_vec!(test_borrowing_a_vec_of_64_leaves_nothing, 64);
a_borrowed_vec!(test_borrowing_a_vec_of_128_leaves_nothing, 128);
a_borrowed_vec!(test_borrowing_a_vec_of_512_leaves_nothing, 512);
a_borrowed_vec!(test_borrowing_a_vec_of_1024_leaves_nothing, 1024);
a_borrowed_vec!(test_borrowing_a_vec_of_4096_leaves_nothing, 4096);
a_borrowed_vec!(test_borrowing_a_vec_of_16384_leaves_nothing, 16384);
a_borrowed_vec!(test_borrowing_a_vec_of_65536_leaves_nothing, 65536);

// ============================================================================
// ZeroizingMutGuard<Wide>
// ============================================================================

/// What the guard borrowed is found while the guard holds it.
#[test]
fn test_a_borrowed_wide_value_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = capture(|| ZeroizingMutGuard::from(&mut source));

        hold_on(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes borrowed, and kept");

    core::hint::black_box(&source);

    Ok(())
}

/// Borrowing four kilobytes leaves nothing once the guard is let go.
///
/// The shape that caught the other guard: there, the swap moved the value and
/// left sixteen bytes of it in a vector register on `aarch64`. Here nothing is
/// moved, so there should be nothing to find.
#[test]
fn test_borrowing_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: inside the capture, because the drop is the operation.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes borrowed");

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard: ownership
// ============================================================================

/// A borrowing guard given away leaves nothing where it was.
///
/// What travels is a `&mut`, so there is nothing for the move to copy. This is
/// the test that says so rather than the type signature.
#[test]
fn test_a_borrowing_guard_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation.
        capture(|| let_go(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a borrowing guard given away",
    );

    Ok(())
}
