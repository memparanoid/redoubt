// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The instrument: everything reserved before it is needed, and then a fork.

use crate::analysis::memory::{Subject, analyse, elsewhere};
use crate::analysis::report::Report;
use crate::analysis::score::{counted, runs};
use crate::analysis::state::{COUNT, FOUND, ForensicState, RUNS, SCORE, SWEPT, WIDEST};
use crate::errors::Reason;

/// The instrument, holding everything it will need before it needs it.
///
/// # Why this is a value and not a function
///
/// Whatever runs between an operation finishing and the memory being frozen is
/// written onto the stack the operation just used, over the frames that are the
/// whole reason to look. Reserving the block and parsing the mappings cost a
/// kilobyte and a half of that, and a kilobyte and a half of stack is where a
/// spilled register lives.
///
/// So all of it moves to before. The caller builds this ahead of the operation
/// — the block reserved, the needle in it — and when the photograph is finally
/// taken the only thing left to do is `fork`. What that leaves is the two or
/// three frames between here and the call itself, which is as small as it goes:
/// a call pushes a return address whatever else it does.
///
/// ```no_run
/// # use redoubt_forensics::{Forensics, Reason};
/// # fn operation() {}
/// # fn main() -> Result<(), Reason> {
/// # let needle: Vec<u8> = Vec::new();
/// let mut watch = Forensics::watching(&needle)?;
///
/// let before = watch.snapshot()?;
/// operation();
/// let after = watch.snapshot()?;
///
/// println!("{}", after.against(&before));
/// # Ok(())
/// # }
/// ```
pub struct Forensics {
    state: ForensicState,
}

impl Forensics {
    /// Everything reserved, and nothing photographed yet.
    ///
    /// `needle` is the secret backwards, for the reason
    /// [`crate::occurrences_reversed`] takes it backwards: what the caller
    /// holds when the photograph is taken is in the photograph, and the
    /// reversed bytes are not the secret and never were. It is turned around
    /// on the far side of the fork, in a process that does not come back.
    ///
    /// Build it before the operation being measured. Building it after is the
    /// mistake the whole shape of this is for.
    ///
    /// Which register capture this machine gets is settled here, for the same
    /// reason everything else is reserved here: working it out is a branch and
    /// an atomic load, and there is no room for either at the moment a capture
    /// is taken. Asked once, now, and never again.
    ///
    /// # Errors
    ///
    /// [`Reason::Needle`], and only that: nothing has been asked of the
    /// kernel yet.
    pub fn watching(needle: &[u8]) -> Result<Self, Reason> {
        crate::spiller::pick_spiller();

        let mut state = ForensicState::default();

        if !state.hold(needle, true) {
            return Err(Reason::Needle);
        }

        Ok(Self { state })
    }

    /// One photograph, weighed.
    ///
    /// # Errors
    ///
    /// Every [`Reason`] but [`Reason::Needle`]. A refusal that arrived as zero
    /// would read exactly like a clean process, which is the one mistake this
    /// must not make.
    #[inline(always)]
    pub fn snapshot(&mut self) -> Result<Report, Reason> {
        elsewhere(&mut self.state, runs)?;

        Ok(Report {
            found: self.state.read(FOUND) == 1,
            score: self.state.read(SCORE),
            swept: self.state.read(SWEPT),
            widest: self.state.read(WIDEST),
            runs: self.state.read(RUNS),
        })
    }

    /// One photograph, from nothing.
    ///
    /// Convenient and blind in one direction: reserving the block happens here
    /// rather than before, so the kilobyte and a half of stack below the caller
    /// is written over on the way in. Fine for anything on the heap, which is
    /// most of it — and no use at all for a spill. Use [`Self::watching`] when
    /// the answer is about the stack.
    ///
    /// # Errors
    ///
    /// Any [`Reason`].
    pub fn snapshot_reversed(needle: &[u8]) -> Result<Report, Reason> {
        Self::watching(needle)?.snapshot()
    }
}

/// How many times those bytes are in this process's writable memory.
///
/// # Errors
///
/// Any [`Reason`].
pub fn occurrences(needle: &[u8]) -> Result<usize, Reason> {
    exactly(needle, false)
}

/// The same count, for the needle read from its last byte to its first.
///
/// What a caller reverses is the copy it is holding, and what it is then
/// asking is whether a second copy — one nobody reversed — is anywhere. The
/// bytes it hands over are not the secret and never were, so asking does not
/// add to the answer.
///
/// # Errors
///
/// Any [`Reason`].
pub fn occurrences_reversed(needle: &[u8]) -> Result<usize, Reason> {
    exactly(needle, true)
}

fn exactly(needle: &[u8], backwards: bool) -> Result<usize, Reason> {
    let mut state = ForensicState::default();

    if !state.hold(needle, backwards) {
        return Err(Reason::Needle);
    }

    analyse(&mut state, counted)?;

    Ok(state.read(COUNT) as usize)
}

/// What the analysis is handed and what it owes back.
///
/// A photograph somebody else took, a block somebody else reserved, and either
/// the numbers written into that block or the reason there are none.
pub(crate) type Work = fn(&mut ForensicState, &Subject) -> Result<(), Reason>;
