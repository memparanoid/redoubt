// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Several needles over one photograph, each held to an absence.

use crate::analysis::report::Report;
use crate::errors::Reason;
use crate::forensics::Forensics;
use crate::verdicts::leaves_nothing;

/// Needles weighed in one photograph, each with its name and its photograph
/// from before.
pub struct Watching {
    forensics: Forensics,
    names: Vec<&'static str>,
    reports_before: Vec<Report>,
}

impl Watching {
    /// Every needle watched, each a secret backwards, and the photograph from
    /// before taken now, while nothing holds them yet.
    ///
    /// # Errors
    ///
    /// Any [`Reason`].
    pub fn start(needles: &[(&'static str, &[u8])]) -> Result<Self, Reason> {
        let names = needles.iter().map(|(name, _)| *name).collect();
        let held: Vec<&[u8]> = needles.iter().map(|(_, needle)| *needle).collect();

        let mut forensics = Forensics::watching_each(&held)?;
        let reports_before = forensics.snapshot_each()?;

        Ok(Self {
            forensics,
            names,
            reports_before,
        })
    }

    /// Asserts that nothing of any needle is left, each named in what fails.
    ///
    /// # Errors
    ///
    /// Every [`Reason`] but [`Reason::Needle`].
    pub fn none_left(&mut self, what: &str) -> Result<(), Reason> {
        let reports_after = self.forensics.snapshot_each()?;

        for ((name, report_before), report_after) in self
            .names
            .iter()
            .zip(&self.reports_before)
            .zip(&reports_after)
        {
            leaves_nothing(
                report_before,
                report_after,
                &format!("{what}, of the {name}"),
            );
        }

        Ok(())
    }
}
