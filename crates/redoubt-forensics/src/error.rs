// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Why a photograph could not be taken.
//!
//! # Why this is not an `Option`
//!
//! A refusal that arrives as zero reads exactly like a clean process, and that
//! is the one mistake this crate must not make. So a photograph that could not
//! be taken says so — and says which of the several quite different things
//! went wrong, because "more mappings than there was room for" and "this
//! kernel will not let a child trace itself" want opposite fixes.
//!
//! # How it crosses back
//!
//! Everything past [`Reason::NoFork`] happens in a process that does not come
//! back, so the reason travels the way every other finding does: as a number
//! in the result block, through the pipe. It is the same word that used to
//! carry a `1` for success.

use core::fmt;

/// What stopped a photograph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Reason {
    /// Nothing to look for, or more to look for than the window is wide.
    ///
    /// The only one of these that is decided before anything forks.
    Needle,
    /// No pipe, so the analyst would have had nowhere to answer.
    NoPipe,
    /// No analyst.
    NoFork,
    /// An analyst that never answered. It died, or it was killed.
    NoAnswer,
    /// The analyst forked, but the photograph would not hold still —
    /// `PTRACE_TRACEME` refused, or the stop never arrived.
    ///
    /// A kernel with `ptrace_scope` locked down does this.
    NoPhotograph,
    /// `/proc/<pid>/maps` would not open, would not read, or held nothing
    /// writable, which cannot be true of a running process.
    NoMappings,
    /// More writable mappings than there was room to record.
    ///
    /// The room is reserved before the operation and cannot grow afterwards,
    /// which is the whole reason it is reserved. A process this fragmented
    /// needs the room made bigger, not the sweep made cleverer.
    TooManyMappings,
    /// More blocks of this crate's own in the photograph than there was room
    /// to skip.
    ///
    /// Every live instrument is one, so this means a great many of them at
    /// once.
    TooManyBlocks,
}

/// Success, as it travels in the result block.
pub(crate) const DONE: u64 = 1;

impl Reason {
    /// How this travels back from a process that does not return.
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::Needle => 2,
            Self::NoPipe => 3,
            Self::NoFork => 4,
            Self::NoAnswer => 5,
            Self::NoPhotograph => 6,
            Self::NoMappings => 7,
            Self::TooManyMappings => 8,
            Self::TooManyBlocks => 9,
        }
    }

    /// The other way, for a word that came back through the pipe.
    ///
    /// Anything unaccounted for is [`Self::NoAnswer`]: a word that is neither
    /// success nor a reason is an analyst that did not finish saying what it
    /// meant.
    pub(crate) const fn from_code(code: u64) -> Self {
        match code {
            2 => Self::Needle,
            3 => Self::NoPipe,
            4 => Self::NoFork,
            6 => Self::NoPhotograph,
            7 => Self::NoMappings,
            8 => Self::TooManyMappings,
            9 => Self::TooManyBlocks,
            _ => Self::NoAnswer,
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Needle => "nothing to look for, or more than the window is wide",
            Self::NoPipe => "no pipe for the analyst to answer through",
            Self::NoFork => "no analyst",
            Self::NoAnswer => "the analyst never answered",
            Self::NoPhotograph => "the photograph would not hold still",
            Self::NoMappings => "no writable mappings could be read",
            Self::TooManyMappings => "more writable mappings than there was room for",
            Self::TooManyBlocks => "more of this crate's own blocks than there was room to skip",
        })
    }
}

impl std::error::Error for Reason {}
