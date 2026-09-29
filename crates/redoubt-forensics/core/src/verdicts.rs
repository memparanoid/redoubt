// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a report has to say for a presence, and for an absence.

use crate::analysis::report::{QUIET, Report};

/// Asserts the whole secret was found. Without a presence, an absence cannot be
/// told apart from a sweep that reaches nowhere.
pub fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// Asserts the secret is gone where no photograph could be taken before it
/// existed: not whole, and no run past [`QUIET`].
pub fn leaves_no_copy(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    no_copy(report, what);
}

/// Asserts the secret is gone: not whole, no run past [`QUIET`], and a score
/// that did not move against a photograph taken while nothing held it yet.
/// Each alone passes a process that kept part of it.
pub fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing held yet");
    report_after.summary_against(report_before, what);
    println!();

    no_copy(report_after, what);

    let delta = report_after.against(report_before);

    assert!(
        delta.is_noise(),
        "{what} moved the score past chance: {delta}"
    );
}

/// What every absence asserts, with or without a photograph before.
fn no_copy(report: &Report, what: &str) {
    // Assert zeroization!
    assert!(
        !report.found,
        "the whole secret was left behind by {what}: {report}"
    );

    assert!(
        report.widest <= QUIET,
        "a run of {} bytes of the secret was left behind by {what}, and {QUIET} \
         is what memory has by accident: {report}",
        report.widest,
    );
}
