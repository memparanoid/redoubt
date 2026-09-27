// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Why a photograph could not be taken, and what a test says when the work it
//! photographed could not be done either.
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
    /// The stack has no floor that can be read from end to end.
    ///
    /// The process's first thread grows its stack on demand, so the pages
    /// below the stack pointer are not all there and a copy of the window
    /// faults. A thread that was spawned has one mapping, made whole when the
    /// thread was made.
    NoFloor,
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
            Self::NoFloor => 10,
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
            10 => Self::NoFloor,
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
            Self::NoFloor => "the stack has no floor that can be read from end to end",
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

/// Anything that can stop a measurement: the photograph, or the work being
/// photographed.
///
/// # Why this is exported at all
///
/// [`Reason`] is enough for most tests, where the operation cannot fail and the
/// only thing that can go wrong is the photograph. A test that measures
/// fallible work — encoding, sealing, opening — has a second source of error
/// that `Reason` has nothing to say about, and needs one type that reaches
/// both.
///
/// Every such test would otherwise write that type itself, and it is not one
/// line: the two constraints below are invisible in the result and each one is
/// a compile error found the hard way. Written once here, they are right
/// everywhere.
///
/// # Why not a boxed `dyn Error`
///
/// A bare one implements `From` of five different things — `&str`, `String`,
/// `Cow`, any `E: Error`, and the core's reflexive one. Solving
/// `Box<_>: From<?E>` with the error still unknown leaves five candidates and
/// `E0283`, so every measured block would have to name its own error type to
/// say which. A newtype has one candidate, and nothing has to be named.
///
/// # Why it does not implement `Error`
///
/// The blanket `From` below would then overlap with the core's own
/// `impl<T> From<T> for T` at `T = AnyError`, which does not compile. Nothing
/// needs it to: a test's error is only ever `Debug`, which is all the harness
/// asks for.
pub struct AnyError(Box<dyn std::error::Error + Send + Sync>);

impl<E: std::error::Error + Send + Sync + 'static> From<E> for AnyError {
    fn from(why: E) -> Self {
        Self(Box::new(why))
    }
}

/// Forwarded, so a failing test names the error it hit and not this wrapper.
impl fmt::Debug for AnyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}
