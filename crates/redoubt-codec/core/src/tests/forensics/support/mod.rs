// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{QUIET, Report};

use needles::SECRET;

/// Writes the secret over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// Takes the value by move and drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value by move and never drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// Asserts the secret was found. Without a presence, an absence cannot be told
/// apart from a sweep that reaches nowhere.
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

/// Asserts the secret is gone: not whole, no run past `QUIET`, and a score that
/// did not move. Each alone passes a process that kept part of it.
pub(crate) fn leaves_nothing(
    report_before: &Report,
    before: &str,
    report_after: &Report,
    what: &str,
) {
    println!();
    report_before.summary(before);
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret was left behind by {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes of the secret was left behind by {what}, and {QUIET} \
         is what memory has by accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(
        delta.is_noise(),
        "{what} moved the score past chance: {delta}"
    );
}
