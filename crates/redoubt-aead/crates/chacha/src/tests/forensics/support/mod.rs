// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod keystream;
pub(crate) mod needles;

use std::println;
use std::vec::Vec;

use redoubt_forensics::{AnyError, Forensics, QUIET, Report};

/// A needle, built from its last byte to its first and never turned around: the
/// forward bytes must not exist in this process.
pub(crate) fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// `from` into somewhere the caller owns, through the copy that erases what it
/// used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8], from: &[u8]) {
    assert_eq!(into.len(), from.len(), "a planting of the wrong width");

    // SAFETY: both are as long as each other, checked above, and a constant
    // and a destination the caller owns are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };
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

/// One watch per value an operation holds, each read from the same capture.
pub(crate) struct Watching {
    watches: Vec<(&'static str, Forensics, Report)>,
}

impl Watching {
    /// Every needle watched, and each photographed before anything holds it.
    pub(crate) fn start(needles: &[(&'static str, &[u8])]) -> Result<Self, AnyError> {
        let mut watches = Vec::with_capacity(needles.len());

        for (name, needle) in needles {
            let mut watch = Forensics::watching(&backwards(needle))?;
            let before = watch.snapshot()?;

            watches.push((*name, watch, before));
        }

        Ok(Self { watches })
    }

    /// Asserts that nothing of any of them is left.
    pub(crate) fn none_left(&mut self, what: &str) -> Result<(), AnyError> {
        for (name, watch, before) in &mut self.watches {
            leaves_nothing(
                before,
                &watch.snapshot()?,
                &std::format!("{what}, of the {name}"),
            );
        }

        Ok(())
    }
}

/// Asserts the needle is gone: not whole, no run past `QUIET`, and a score that
/// did not move. Each alone passes a process that kept part of it.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing held yet");
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
