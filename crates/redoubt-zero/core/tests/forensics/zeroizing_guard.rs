// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # Why each section asks about three `T`
//!
//! `ZeroizingGuard::from_mut` swaps the caller's value with a boxed default,
//! and what the swap moves depends on `T`: a `Vec<u8>` moves its header and the
//! secret stays in its heap block; `[u8; 32]` moves the secret itself through
//! registers; four kilobytes inline moves through a call into the C library.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero_core::{FastZeroizable, ZeroizationProbe, ZeroizingGuard};

use crate::support::needles::{SECRET, backwards};
use crate::support::{Wide, giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// ZeroizingGuard::drop
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
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(guard));
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec dropped");

    Ok(())
}

#[test]
fn test_dropping_a_guarded_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array dropped");

    Ok(())
}

#[test]
fn test_dropping_a_guarded_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes dropped");

    Ok(())
}

// ============================================================================
// ZeroizingGuard: ownership
// ============================================================================

#[test]
fn test_a_guarded_vec_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(guard));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a guarded vec given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

#[test]
fn test_a_guarded_array_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(guard));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a guarded array given away, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_guarded_wide_value_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(guard));
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes given away, and kept");

    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_guarded_vec_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(guard));
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec given away");

    Ok(())
}

#[test]
fn test_a_guarded_array_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array given away");

    Ok(())
}

#[test]
fn test_a_guarded_wide_value_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    forensics!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(guard));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes given away");

    Ok(())
}

// ============================================================================
// ZeroizingGuard::from_mut
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

    core::hint::black_box(&source);

    Ok(())
}

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
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
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

#[test]
fn test_guarding_an_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let guard = capture(|| ZeroizingGuard::from_mut(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array guarded");

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
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes guarded");

    Ok(())
}

// ============================================================================
// ZeroizingGuard::from_default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it guards a default value."]
fn test_guarding_a_default_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// ZeroizingGuard::deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_dereferencing_a_guard_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// ZeroizingGuard::deref_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_dereferencing_a_guard_mutably_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// ZeroizingGuard::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_guarded_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let mut guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| guard.fast_zeroize());
    });

    core::mem::forget(guard);
    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_guarded_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let mut guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| guard.fast_zeroize());
    });

    core::mem::forget(guard);
    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_guarded_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let mut guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| guard.fast_zeroize());
    });

    core::mem::forget(guard);
    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes zeroized");

    Ok(())
}

// ============================================================================
// ZeroizingGuard::is_zeroized
// ============================================================================

#[test]
fn test_a_guarded_vec_probed_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a guarded vec probed, and kept");

    core::mem::forget(guard);
    drop(core::hint::black_box(source));

    Ok(())
}

#[test]
fn test_a_guarded_array_probed_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a guarded array probed, and kept");

    core::mem::forget(guard);
    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_a_guarded_wide_value_probed_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes probed, and kept");

    core::mem::forget(guard);
    core::hint::black_box(&source);

    Ok(())
}

#[test]
fn test_probing_a_guarded_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec probed");

    Ok(())
}

#[test]
fn test_probing_a_guarded_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let guard = ZeroizingGuard::from_mut(&mut source);

    forensics!({
        capture(|| core::hint::black_box(guard.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array probed");

    Ok(())
}

#[test]
fn test_probing_a_guarded_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingGuard::from_mut(&mut source);

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
