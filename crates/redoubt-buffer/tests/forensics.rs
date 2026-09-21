// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a guarded page shows a sweep, and what reading one leaves behind.
//!
//! # What is measured here
//!
//! Not what the page holds: that is out of the sweep's reach whatever it is.
//! What is measured is the operations that handle the page — the unprotect, the
//! slice handed out, the protect on the way back — and whether any of them left
//! a copy in a register or on the stack it used, which is where `capture!()`
//! reads.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the secret could be. `nextest`, not `cargo test`.

#![cfg(all(unix, target_os = "linux"))]

use redoubt_buffer::{Buffer, BufferError, PageBuffer, ProtectionStrategy};
use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// Not a plain assignment, which is whatever move the compiler emits: the test
/// does not get to cause the thing it is measuring.
fn giving(into: &mut [u8]) {
    // SAFETY: `into` is the buffer's own length, which is the secret's, and a
    // constant and a mapped page are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), SECRET.len()) };
}

/// A reader that takes the slice and does nothing a compiler may remove. What
/// the absence below asks is whether handing the contents over is enough to
/// leave a copy behind, so this must not be the thing that leaves it.
fn used(what: &[u8]) {
    core::hint::black_box(what);
}

fn filled() -> Result<PageBuffer, AnyError> {
    let mut buffer = PageBuffer::new(ProtectionStrategy::MemProtected, SECRET.len())?;

    buffer.open_mut(&mut |slice: &mut [u8]| {
        giving(slice);

        Ok(())
    })?;

    Ok(buffer)
}

/// The photograph says the secret is there, which is what makes the absence
/// under it mean anything.
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
fn leaves_nothing(report_before: &Report, report_after: &Report, before: &str, what: &str) {
    println!();
    report_before.summary(before);
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
// PageBuffer::open
// ============================================================================

/// The photograph is taken from inside the closure, where a copy exists at all.
/// This is the presence both absences below rest on: the sweep reaches where a
/// copy of these bytes lands, so a clean answer afterwards is about there being
/// no copy.
#[test]
fn test_a_copy_taken_out_of_the_page_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;
    let mut buffer = filled()?;

    let mut inside = None;

    forensics!({
        let read = buffer.open(&mut |slice: &[u8]| {
            let taken = slice.to_vec();

            inside = watch.snapshot().ok();

            drop(core::hint::black_box(taken));

            Ok(())
        });

        capture!();
        read?;
    });

    let report = inside.expect("no photograph was taken inside the page");

    is_found(&report, "a copy of the secret, outside the page");

    core::hint::black_box(&buffer);

    Ok(())
}

/// The page itself is out of the sweep's reach, open or closed.
///
/// A guarded page is `PROT_NONE` at rest and `PROT_WRITE` alone while it is
/// read through. Neither is readable, so neither is swept, and the secret is
/// there while the sweep says nothing.
///
/// That is a limit of the instrument and not a property of this crate, so read
/// a failure the other way round: the sweep reached a guarded page, and every
/// absence resting on this — here, and in any consumer that keeps a secret in
/// one — is now answering a different question and has to be read again.
#[test]
fn test_the_page_itself_is_out_of_the_sweep_s_reach() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PageBuffer::new(ProtectionStrategy::MemProtected, SECRET.len())?;

        let wrote = held.open_mut(&mut |slice: &mut [u8]| {
            giving(slice);

            Ok(())
        });

        capture!();
        wrote?;

        // CORRECTNESS: the page is left holding the secret, which is what the
        // absence below is about. Releasing it here empties and unmaps it, and
        // the absence is then about a page that is not there.
        core::mem::forget(held);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing written yet",
        "a page closed over the secret",
    );

    Ok(())
}

// ============================================================================
// PageBuffer::open
// ============================================================================

/// Reading it out leaves no copy behind.
///
/// The contents are handed to something that holds them for as long as the
/// closure runs and keeps nothing, so what an absence afterwards is about is
/// the opening itself: the unprotect, the slice, and the protect on the way
/// out.
#[test]
fn test_reading_a_page_out_leaves_nothing_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut buffer = filled()?;

    let report_before = watch.snapshot()?;

    forensics!({
        let read_result = buffer.open(&mut |slice: &[u8]| {
            used(slice);

            Ok::<(), BufferError>(())
        });

        capture!();
        read_result?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "the page filled, and closed",
        "a page read out and closed again",
    );

    core::hint::black_box(&buffer);

    Ok(())
}

// ============================================================================
// Drop for PageBuffer
// ============================================================================

#[test]
fn test_dropping_a_page_leaves_nothing_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let held = filled()?;

        // CORRECTNESS: before the capture. The release is the subject, so what
        // the photograph reads is the stack and the registers it left on its
        // way through.
        drop(held);

        capture!();
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing written yet",
        "a page dropped",
    );

    Ok(())
}

// ============================================================================
// PageBuffer, moved
// ============================================================================

/// Takes the buffer by value, so the caller is left holding the slot it was
/// moved out of.
fn let_go(buffer: PageBuffer) {
    drop(buffer);
}

/// What a move copies is the mapping's address and not its contents, so the
/// slot left behind holds no secret. Read a failure as the page having grown
/// into the struct, where a move carries the bytes and empties nothing.
#[test]
fn test_moving_a_page_leaves_nothing_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let held = filled()?;

        // CORRECTNESS: before the capture. The move is the subject, so what
        // the photograph reads is the slot it was moved out of.
        let_go(held);

        capture!();
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing written yet",
        "a page moved",
    );

    Ok(())
}
