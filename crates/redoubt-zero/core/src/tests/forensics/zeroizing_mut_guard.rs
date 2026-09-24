// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::{FastZeroizable, ZeroizationProbe, ZeroizingMutGuard};

use crate::tests::forensics::support::needles::{SECRET, backwards};
use crate::tests::forensics::support::{Wide, giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// ZeroizingMutGuard::drop
// ============================================================================

macro_rules! a_borrowed_vec_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let guard = ZeroizingMutGuard::from(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(guard));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a borrowed vec of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

a_borrowed_vec_dropped!(test_dropping_a_guard_over_a_vec_of_32_leaves_nothing, 32);
a_borrowed_vec_dropped!(test_dropping_a_guard_over_a_vec_of_64_leaves_nothing, 64);
a_borrowed_vec_dropped!(test_dropping_a_guard_over_a_vec_of_128_leaves_nothing, 128);
a_borrowed_vec_dropped!(test_dropping_a_guard_over_a_vec_of_512_leaves_nothing, 512);
a_borrowed_vec_dropped!(
    test_dropping_a_guard_over_a_vec_of_1024_leaves_nothing,
    1024
);
a_borrowed_vec_dropped!(
    test_dropping_a_guard_over_a_vec_of_4096_leaves_nothing,
    4096
);
a_borrowed_vec_dropped!(
    test_dropping_a_guard_over_a_vec_of_16384_leaves_nothing,
    16384
);
a_borrowed_vec_dropped!(
    test_dropping_a_guard_over_a_vec_of_65536_leaves_nothing,
    65536
);

#[test]
fn test_dropping_a_guard_over_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "four kilobytes borrowed, dropped",
    );

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard: ownership
// ============================================================================

#[test]
fn test_a_borrowing_guard_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(guard));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a borrowing guard given away, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_borrowing_guard_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
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

// ============================================================================
// ZeroizingMutGuard::from
// ============================================================================

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

#[test]
fn test_borrowing_a_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingMutGuard::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a vec borrowed");

    Ok(())
}

#[test]
fn test_borrowing_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = capture(|| ZeroizingMutGuard::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes borrowed");

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard::deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_dereferencing_a_borrowing_guard_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// ZeroizingMutGuard::deref_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_dereferencing_a_borrowing_guard_mutably_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// ZeroizingMutGuard::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_borrowed_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let mut guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| guard.fast_zeroize());
    });

    core::mem::forget(guard);
    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a borrowed vec zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_borrowed_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let mut guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| guard.fast_zeroize());
    });

    core::mem::forget(guard);
    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "four kilobytes borrowed, zeroized",
    );

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard::is_zeroized
// ============================================================================

#[test]
fn test_a_borrowed_vec_probed_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a borrowed vec probed, and kept");

    drop(guard);
    drop(core::hint::black_box(source));

    Ok(())
}

#[test]
fn test_a_borrowed_wide_value_probed_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes probed, and kept");

    drop(guard);
    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_probing_a_borrowed_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a borrowed vec probed");

    Ok(())
}

#[test]
fn test_probing_a_borrowed_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingMutGuard::from(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes probed");

    Ok(())
}
