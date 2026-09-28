// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{QUIET, Report};

/// A needle built from its last byte to its first and never turned around: the
/// forward bytes must not exist in this process.
pub(crate) fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// `of` in a heap block, through the probed copy: a compiler copy would leave
/// residue the test caused itself.
pub(crate) fn hold(of: &[u8]) -> Vec<u8> {
    let mut held = vec![0_u8; of.len()];

    // SAFETY: `held` was just allocated, so it overlaps nothing, and both are
    // `of.len()` bytes.
    unsafe { redoubt_mem::copy_nonoverlapping(of.as_ptr(), held.as_mut_ptr(), of.len()) };

    held
}

pub(crate) fn wipe(held: &mut [u8]) {
    // SAFETY: `held` is a live slice of `held.len()` bytes, borrowed exclusively.
    unsafe { redoubt_mem::zeroize(held.as_mut_ptr(), held.len()) };
}

/// Asserts the needle was found. Without a presence, an absence cannot be told
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

/// Asserts the needle is gone: not whole, no run past `QUIET`, and a score that
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
