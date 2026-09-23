// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a secret leaves behind on its way into the box that holds it.
//!
//! # Two tests for every claim
//!
//! An absence on its own says nothing: a sweep that reaches nowhere reports a
//! clean process, and so does a secret that was put away properly. So each
//! section opens with the same operation run against a value that is never let
//! go, and that one has to be **found**. Whatever the rest of the section
//! reports is worth exactly as much as that.
//!
//! # Why no test here is about a `u64`
//!
//! Eight bytes is `QUIET`, the width memory reaches by accident, so an absence
//! over a value that narrow is not a weak answer — it is no answer. The
//! narrowest primitive this can be asked about is a `u128`, and the answer for
//! the `u64` a caller actually stores is reached the other way: it is the same
//! generic code, measured at a width the instrument can see.
//!
//! # What goes inside the block
//!
//! The source is filled outside it — that is the test's own doing, and the
//! crate does not answer for it. Everything the crate does goes in, from the
//! value being taken to the box being let go.

#![cfg(all(unix, target_os = "linux"))]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
use redoubt_secret::RedoubtSecret;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Sixteen distinct bytes as a `u128`, which is the narrowest primitive an
/// absence can be measured over: eight is `QUIET`, and no sweep tells that
/// from noise.
const NARROW: u128 = u128::from_le_bytes([
    0x3B, 0xD5, 0x62, 0xF7, 0x18, 0xAC, 0x4E, 0x90, 0x27, 0xEB, 0x5D, 0x81, 0xC6, 0x0F, 0xA3, 0x74,
]);

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The `u128` needle, built the same way and for the same reason.
fn narrow_backwards() -> Vec<u8> {
    NARROW.to_le_bytes().iter().rev().copied().collect()
}

/// The secret into somewhere the caller already owns, by the copy that erases
/// what it used.
///
/// Not a plain assignment, which is whatever move the compiler emits: the test
/// does not get to cause the thing it is measuring.
fn giving(into: &mut [u8; 32]) {
    // SAFETY: both are thirty-two bytes, and a constant and a local are
    // different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), SECRET.len()) };
}

/// Takes the value and lets it go, which runs its drop somewhere the caller
/// cannot see.
///
/// Not inlined: a move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value the same way and never lets it go.
///
/// The other half of each pair. The move is the same move, so whatever it
/// leaves behind is the same; what changes is that whoever took it is still
/// holding the secret when the photograph is taken.
#[inline(never)]
fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// The three things an absence has to survive.
///
/// The whole secret is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing taken yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// RedoubtSecret::from
// ============================================================================

#[test]
fn test_what_was_taken_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        hold_on(held);
    });

    is_found(&watch.snapshot()?, "a secret taken from a source, and kept");

    Ok(())
}

#[test]
fn test_taking_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let report_before = watch.snapshot()?;

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret taken");

    Ok(())
}

#[test]
fn test_taking_a_narrow_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&narrow_backwards())?;

    let mut source = NARROW;

    let report_before = watch.snapshot()?;

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a primitive secret taken",
    );

    Ok(())
}

// ============================================================================
// RedoubtSecret::replace
// ============================================================================

#[test]
fn test_what_replaced_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtSecret::<[u8; 32]>::default();

        capture(|| held.replace(&mut source));

        hold_on(held);
    });

    is_found(&watch.snapshot()?, "a secret replaced into, and kept");

    Ok(())
}

#[test]
fn test_replacing_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = RedoubtSecret::<[u8; 32]>::default();

        capture(|| held.replace(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret replaced");

    Ok(())
}

// ============================================================================
// RedoubtSecret: ownership
// ============================================================================

/// What a move copies is the box's address and not what is behind it, so the
/// slot left behind holds no secret. Read a failure as the value having come
/// out of the box and into the struct, where a move carries the bytes and
/// empties nothing.
#[test]
fn test_a_secret_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let held = RedoubtSecret::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether the move itself leaves a copy in the
        // registers or the stack it used.
        capture(|| let_go(held));
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret given away");

    Ok(())
}

// ============================================================================
// RedoubtSecret::drop
// ============================================================================

/// Dropping the secret leaves nothing.
#[test]
fn test_dropping_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let held = RedoubtSecret::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is what the drop itself leaves in the registers
        // or the stack it used.
        capture(|| drop(held));
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret dropped");

    Ok(())
}
