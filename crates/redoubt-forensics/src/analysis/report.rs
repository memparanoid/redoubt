// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What one photograph came to, and what two of them say between them.
//!
//! # One number is unreadable
//!
//! A score on its own is a number about a process, not about an operation. The
//! reading is always the difference: a photograph, the operation, another
//! photograph, and [`Report::against`]. What is in [`Change`] is what the
//! operation did.

use core::fmt;

use crate::analysis::score::NOISE;

/// The widest run a process that is holding nothing may have.
///
/// It lives here so that callers asserting an absence share one number rather
/// than each picking their own. Unlike the ceiling [`Change::is_noise`] uses,
/// it is in the same units as the field it is compared against, so there is
/// no arithmetic between the two that could drift.
pub const QUIET: u64 = 8;

/// What one photograph came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Whether the whole secret was there, compared byte for byte.
    ///
    /// This one is exact, and it is what a positive control is for: a sweep
    /// that reaches nowhere answers `false` to everything, and so does a clean
    /// process.
    pub found: bool,
    /// Bits of evidence, summed over every run and floored at what the memory
    /// would have thrown up by chance.
    pub score: u64,
    /// How many bytes were read to arrive at it.
    pub swept: u64,
    /// The longest run there was.
    pub widest: u64,
    /// How many runs were closed at all, noise included.
    pub runs: u64,
}

/// What an operation did, between one photograph and the next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Change {
    /// What the score did. Up is the direction that means something.
    pub score: i128,
    /// What the longest run did.
    pub widest: i64,
    /// What the number of runs did, which is mostly the process breathing.
    pub runs: i128,
    /// How much more memory there was to read.
    ///
    /// Worth reading before anything else in here. Two photographs of a
    /// process that did something in between are two photographs of different
    /// amounts of memory, and a zero here says the second one is the first
    /// one — nothing ran, or nothing was seen to run, and every other number
    /// is a comparison of a thing with itself.
    pub swept: i128,
    /// Whether the whole secret turned up where it had not before.
    pub surfaced: bool,
}

impl Report {
    /// What changed between an earlier photograph and this one.
    #[must_use]
    pub fn against(&self, before: &Self) -> Change {
        Change {
            score: i128::from(self.score) - i128::from(before.score),
            widest: self.widest as i64 - before.widest as i64,
            runs: i128::from(self.runs) - i128::from(before.runs),
            swept: i128::from(self.swept) - i128::from(before.swept),
            surfaced: self.found && !before.found,
        }
    }
}

impl Change {
    /// Whether this rise in score is what chance throws up, or evidence.
    ///
    /// The ceiling is a fixed number of bits and not a number anybody chose
    /// for this process: the score's own arithmetic has already taken the
    /// memory out of it, so a score means the same thing in a small process
    /// and a large one. [`crate::analysis::score::NOISE`] carries the
    /// reasoning.
    ///
    /// A score that fell is not a rise, and is chance by the same token.
    #[must_use]
    pub fn is_noise(&self) -> bool {
        self.score <= NOISE
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "score {:>12}  widest {:>5}  runs {:>14}  swept {:>13}  whole {}",
            self.score,
            self.widest,
            self.runs,
            self.swept,
            if self.found { "yes" } else { "no" },
        )
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "score {:>+13}  widest {:>+6}  runs {:>+15}  swept {:>+14}{}",
            self.score,
            self.widest,
            self.runs,
            self.swept,
            if self.surfaced {
                "  and the whole secret surfaced"
            } else {
                ""
            },
        )
    }
}
