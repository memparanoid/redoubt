// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How much of a secret is left, as one number.
//!
//! # Why a count is the wrong answer
//!
//! Asking whether the secret is somewhere answers the wrong question about
//! what a copy actually leaves. Bytes move in the widths the machine has, so
//! what survives an operation is usually a piece: half of it in a spill slot,
//! a quarter in a scratch buffer nobody named. A search for the whole thing
//! finds none of that, and the zero it returns is true.
//!
//! # Runs
//!
//! So the question is how long a stretch of the secret turns up anywhere, and
//! the sweep answers it with one table: for each pair of byte values, whether
//! the second ever follows the first in the secret. Walking memory, a run is a
//! stretch where every step is one the secret allows; when a step is not, the
//! run closes and its width is tallied.
//!
//! That over-counts, deliberately. It accepts stretches whose every pair is in
//! the secret but which are not in the secret — and the price of that is one
//! bit test per byte of memory rather than a search, which is the difference
//! between sweeping a gigabyte and not being able to. The over-count is the
//! same in every photograph of the same process with the same secret, so it
//! cancels in the difference between two, which is the only place anyone is
//! asked to read it.
//!
//! The exception is [`Report::found`], which is not a run at all: when a run
//! reaches the full width of the secret its bytes are compared against the
//! secret one for one. That one is exact, which is what makes it worth
//! anything as a positive control.
//!
//! # The score
//!
//! A width on its own means nothing without knowing how much memory it was
//! found in — three bytes of anything are in a gigabyte of anything. The
//! chance of one particular step continuing a run is the table's density, so
//! the surprise of a run `w` wide, in bits, is
//!
//! ```text
//! bits(w) = (w - 1) · log2(256 / t)  −  log2(swept)
//! ```
//!
//! where `t` is the average number of successors a byte has in the table. The
//! score is that, summed over every run, and never below zero.
//!
//! Which means the floor moves by itself. A thirty-two byte secret has about
//! one successor per byte, so each step is worth eight bits and runs stop being
//! noise at about five wide. A three kilobyte key has about thirteen, each step
//! is worth four and a bit, and the floor slides out to eight. Nobody picks a
//! threshold.
//!
//! # Two photographs
//!
//! One score is unreadable on its own. The reading is the difference: a
//! photograph before an operation, the operation, a photograph after, and
//! [`Report::against`].

use std::fmt;

use crate::memory::{Subject, analyse, elsewhere, instrument, sweep, within};
use crate::state::{
    COUNT, FOUND, ForensicState, MOST, Parts, RUNS, SCORE, SWEPT, WIDEST,
};

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
/// # use redoubt_forensics::Forensics;
/// # fn operation() {}
/// # let needle: Vec<u8> = Vec::new();
/// let mut watch = Forensics::watching(&needle).expect("no fork");
///
/// let before = watch.snapshot().expect("no photograph");
/// operation();
/// let after = watch.snapshot().expect("no photograph");
///
/// println!("{}", after.against(&before));
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
    #[must_use]
    pub fn watching(needle: &[u8]) -> Option<Self> {
        let mut state = ForensicState::default();

        if !state.hold(needle, true) {
            return None;
        }

        Some(Self { state })
    }

    /// One photograph, weighed.
    ///
    /// `None` when the analysis could not be run at all — no fork, no
    /// `ptrace`, more mappings than there was room for. A refusal that arrived
    /// as zero would read exactly like a clean process, which is the one
    /// mistake this must not make.
    #[must_use]
    #[inline(always)]
    pub fn snapshot(&mut self) -> Option<Report> {
        if !elsewhere(&mut self.state, runs) {
            return None;
        }

        Some(Report {
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
    #[must_use]
    pub fn snapshot_reversed(needle: &[u8]) -> Option<Report> {
        Self::watching(needle)?.snapshot()
    }
}

/// How many times those bytes are in this process's writable memory.
#[must_use]
pub fn occurrences(needle: &[u8]) -> usize {
    exactly(needle, false)
}

/// The same count, for the needle read from its last byte to its first.
///
/// What a caller reverses is the copy it is holding, and what it is then
/// asking is whether a second copy — one nobody reversed — is anywhere. The
/// bytes it hands over are not the secret and never were, so asking does not
/// add to the answer.
#[must_use]
pub fn occurrences_reversed(needle: &[u8]) -> usize {
    exactly(needle, true)
}

fn exactly(needle: &[u8], backwards: bool) -> usize {
    let mut state = ForensicState::default();

    if !state.hold(needle, backwards) {
        return 0;
    }

    if !analyse(&mut state, counted) {
        return 0;
    }

    state.read(COUNT) as usize
}

/// The whole needle, counted where it is whole.
fn counted(state: &mut ForensicState, subject: &Subject) -> bool {
    let of = state.of;
    let backwards = state.backwards;

    let Parts { held, secret, mut skips, maps, result, .. } = state.parts();

    // One block serves every photograph, so the last one's answer goes first.
    result.fill(0);

    // Past the fork, where writing is free: every page touched from here is a
    // new page for this process, and this process is about to not exist.
    if backwards {
        secret[..of].reverse();
    }

    if !instrument(subject, held, &maps, &mut skips) {
        return false;
    }

    let needle = &secret[..of];
    let mut found = 0;

    sweep(subject, held, &maps, &skips, of - 1, |window, _, _| {
        found += within(window, needle, false) as u64;
    });

    result[COUNT] = found;

    true
}

/// Every run, tallied by width, and then weighed.
fn runs(state: &mut ForensicState, subject: &Subject) -> bool {
    let of = state.of;
    let backwards = state.backwards;

    let Parts { held, secret, next, seen, widths, result, mut skips, maps, .. } =
        state.parts();

    // One block serves every photograph, so the last one's answer goes first.
    widths.fill(0);
    result.fill(0);

    if backwards {
        secret[..of].reverse();
    }

    table(&secret[..of], next, seen);

    if !instrument(subject, held, &maps, &mut skips) {
        return false;
    }

    let mut run = 0_usize;
    let mut prev = 0_u8;
    let mut began = 0_usize;
    let mut placed = false;
    let mut whole = false;

    let swept = sweep(subject, held, &maps, &skips, 0, |window, _, breaks| {
        for (i, &byte) in window.iter().enumerate() {
            if run > 0 && follows(next, prev, byte) {
                run += 1;
            } else {
                close(run, widths);

                run = usize::from(holds(seen, byte));
                began = i;
                placed = run > 0;
            }

            prev = byte;

            // The one exact thing in here. A run as wide as the secret is only
            // a run until its bytes are the secret's bytes.
            if run == of
                && placed
                && began + of <= window.len()
                && window[began..began + of] == secret[..of]
            {
                whole = true;
            }
        }

        if breaks {
            close(run, widths);
            run = 0;
        }

        // Whatever is still going carries into the next window, but where it
        // began does not: that index is into a window nobody has any more.
        placed = false;
    });

    let step = density(next);
    let floor = lg2(swept);

    let mut score = 0_u64;
    let mut widest = 0_u64;
    let mut closed = 0_u64;

    for (width, &count) in widths.iter().enumerate() {
        if count == 0 {
            continue;
        }

        closed += count;
        widest = width as u64;

        if width >= 2 {
            let bits = ((width as u64 - 1) * step).saturating_sub(floor) >> 10;

            score += bits.saturating_mul(count);
        }
    }

    result[FOUND] = u64::from(whole);
    result[SCORE] = score;
    result[SWEPT] = swept;
    result[WIDEST] = widest;
    result[RUNS] = closed;

    true
}

/// Which byte may follow which, and which are in the secret at all.
///
/// One bit each, so the secret is not in either table — only the shape of it
/// is, and the shape is what the sweep asks about.
fn table(secret: &[u8], next: &mut [u8], seen: &mut [u8]) {
    next.fill(0);
    seen.fill(0);

    for &byte in secret {
        seen[(byte >> 3) as usize] |= 1 << (byte & 7);
    }

    for pair in secret.windows(2) {
        let (from, to) = (pair[0] as usize, pair[1]);

        next[from * 32 + (to >> 3) as usize] |= 1 << (to & 7);
    }
}

/// Whether `to` ever follows `from` in the secret.
fn follows(next: &[u8], from: u8, to: u8) -> bool {
    next[from as usize * 32 + (to >> 3) as usize] & (1 << (to & 7)) != 0
}

/// Whether the secret has that byte anywhere.
fn holds(seen: &[u8], byte: u8) -> bool {
    seen[(byte >> 3) as usize] & (1 << (byte & 7)) != 0
}

/// One more run of that width, and the widest one there is room to say.
fn close(run: usize, widths: &mut [u64]) {
    if run == 0 {
        return;
    }

    widths[run.min(MOST - 1)] += 1;
}

/// What one step of a run is worth, in bits, to ten binary places.
///
/// The table's density is what makes a step surprising: with one successor per
/// byte a step is a byte, worth eight bits, and with thirteen of them it is
/// worth `log2(256 / 13)`, a little over four. Dividing by the number of bytes
/// that have any successor at all is what keeps a short secret from being
/// judged as if it were a dense one.
fn density(next: &[u8]) -> u64 {
    let mut edges = 0_u64;
    let mut nodes = 0_u64;

    for row in next.chunks(32) {
        let out: u32 = row.iter().map(|byte| byte.count_ones()).sum();

        if out > 0 {
            nodes += 1;
            edges += u64::from(out);
        }
    }

    if edges == 0 || nodes == 0 {
        return 8 * 1024;
    }

    (8 * 1024 + lg2(nodes)).saturating_sub(lg2(edges))
}

/// `log2`, to ten binary places, straight enough for weighing runs.
///
/// The whole part is where the leading bit is; the fraction is what is under
/// it, read as a straight line between one power of two and the next. That is
/// off by at most a tenth of a bit, which is nothing next to a run being one
/// byte wider.
fn lg2(of: u64) -> u64 {
    if of == 0 {
        return 0;
    }

    let whole = u64::from(63 - of.leading_zeros());

    let under = if whole >= 10 {
        of >> (whole - 10)
    } else {
        of << (10 - whole)
    };

    whole * 1024 + (under - 1024)
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
            if self.surfaced { "  and the whole secret surfaced" } else { "" },
        )
    }
}
