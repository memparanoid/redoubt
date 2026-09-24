// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{QUIET, Report};

use needles::SECRET;

/// The secret over and over, into somewhere the caller already owns, by the
/// copy that erases what it used.
///
/// Not `to_vec` and not a plain assignment: both are whatever move the
/// compiler emits, and the test does not get to cause the thing it is
/// measuring.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// What every `AllockedVec` in this file holds.
///
/// As wide as the secret, and never `u8`. A vec of bytes moves its elements one
/// at a time, so a residue it leaves is single bytes scattered over registers
/// that go on overwriting each other — a run of one, which is what memory has
/// by accident and what no sweep can tell from noise. The residue is real and
/// the measurement of it is not: an absence over `u8` elements is not a weak
/// answer, it is no answer.
///
/// Measured. `drain_from` moved its values with a compiler move, which leaves a
/// copy wherever it likes and empties none of them. Over `u8` elements this
/// file read a clean process; over this one it read the whole secret, thirty-two
/// bytes wide.
pub(crate) type Block = [u8; SECRET.len()];

/// How many of those make up a size in bytes.
pub(crate) const fn blocks(of: usize) -> usize {
    of / SECRET.len()
}

/// Takes the value and lets it go, which runs its drop somewhere the caller
/// cannot see.
///
/// What handing one of these to somebody else is. Not inlined: a move within
/// one function is one the optimiser may fold away, and a measurement of what
/// a move leaves has to be sure a move happened.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value the same way and never lets it go.
///
/// The other half of each pair. The move is the same move, so whatever it
/// leaves behind is the same; what changes is that whoever took it is still
/// holding the secret when the photograph is taken.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
///
/// Every absence below it is an absence in the same place, reached the same
/// way. If this one is quiet, the instrument is standing somewhere else and
/// nothing in the section is a measurement.
pub(crate) fn is_found(report: &Report, what: &str) {
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
pub(crate) fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing filled yet");
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
