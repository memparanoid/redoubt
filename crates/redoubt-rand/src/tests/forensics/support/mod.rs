// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{QUIET, Report};

/// As much as a key is.
pub(crate) const WIDE: usize = 32;

/// Every byte back to zero, volatile and one at a time: a `fill` is a call to
/// `memset`, which would put the bytes through the registers this is asking
/// about.
pub(crate) fn wipe(into: &mut [u8]) {
    for at in 0..into.len() {
        // SAFETY: in bounds of a live slice.
        unsafe { into.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// The needle, read from the last byte to the first, volatile and one at a
/// time: a reverse through a vector register would hold the bytes forwards.
pub(crate) fn backwards(of: &[u8]) -> Vec<u8> {
    let mut needle = vec![0_u8; of.len()];

    for at in 0..of.len() {
        // SAFETY: both in bounds of live slices of the same length.
        unsafe {
            needle
                .as_mut_ptr()
                .add(at)
                .write_volatile(of.as_ptr().add(of.len() - 1 - at).read_volatile());
        }
    }

    needle
}

/// Without a presence an absence cannot be told apart from a sweep that reaches
/// nowhere.
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

pub(crate) fn leaves_nothing(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    // Assert zeroization!
    assert!(
        !report.found,
        "the whole of what the call produced is still in this process after \
         {what}: {report}"
    );

    assert!(
        report.widest <= QUIET,
        "a run of {} bytes of it survived {what}, and {QUIET} is what memory \
         has by accident: {report}",
        report.widest,
    );
}

/// An absence where the needle existed before the photograph that opens it,
/// so the score is held to that photograph too.
pub(crate) fn leaves_nothing_since(report_before: &Report, report_after: &Report, what: &str) {
    leaves_nothing(report_after, what);

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}
