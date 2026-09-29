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
//! A run is a candidate and not a finding. The table accepts any stretch
//! whose every pair is in the secret, and that includes stretches the secret
//! never holds: sixteen `8`s walk the pair `88` fifteen times, and the secret
//! has two of them. So when a run closes its bytes are read back out of the
//! ring the sweep keeps, and what is tallied is the widest stretch of the
//! secret inside it — two, for the sixteen `8`s. The table is what keeps the
//! sweep at one bit test per byte of memory; the reading back only happens to
//! runs of three or more, which are rare enough to cost nothing.
//!
//! A run that reads back as wide as the secret is the secret, and that is
//! [`crate::Report::found`]. It is exact, which is what makes it worth
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
//! # What is in here, and what is not
//!
//! Nothing in this file forks, allocates or reads another process. The two
//! entry points are handed a photograph that somebody else took and a block
//! that somebody else reserved; everything below them is arithmetic over
//! bytes, and can be read — and tested — without a process to look at.

use crate::analysis::memory::{Subject, instrument, sweep, within};
use crate::analysis::state::{
    COUNT, EACH, FOUND, ForensicState, MOST, NEEDLES, NEXT, Parts, RUNS, SCORE, SEEN, SWEPT,
    WIDEST,
};
use crate::errors::Reason;

/// The whole needle, counted where it is whole.
pub(crate) fn count(state: &mut ForensicState, subject: &Subject) -> Result<(), Reason> {
    let backwards = state.backwards;

    let Parts {
        held,
        needles,
        of,
        mut skips,
        maps,
        result,
        ..
    } = state.parts();

    let of = of[0] as usize;
    let secret = &mut needles[..of];

    // One block serves every photograph, so the last one's answer goes first.
    result.fill(0);

    // Past the fork, where writing is free: every page touched from here is a
    // new page for this process, and this process is about to not exist.
    if backwards {
        secret[..of].reverse();
    }

    instrument(subject, held, &maps, &mut skips)?;

    let needle = &secret[..of];
    let mut found = 0;

    sweep(subject, held, &maps, &skips, of - 1, |window, _, _| {
        found += within(window, needle, false) as u64;
    });

    result[COUNT] = found;

    Ok(())
}

/// Every run, tallied by width, and then weighed.
pub(crate) fn runs(state: &mut ForensicState, subject: &Subject) -> Result<(), Reason> {
    let many = state.many;
    let backwards = state.backwards;

    let Parts {
        held,
        needles,
        of,
        next,
        seen,
        widths,
        tail,
        lens,
        result,
        mut skips,
        maps,
        ..
    } = state.parts();

    let of = &of[..many];
    let total: usize = of.iter().map(|one| *one as usize).sum();

    // One block serves every photograph, so the last one's answer goes first.
    widths[..total + many].fill(0);
    result.fill(0);

    let mut at = 0;

    for (one, &width) in of.iter().enumerate() {
        let needle = &mut needles[at..at + width as usize];

        if backwards {
            needle.reverse();
        }

        table(
            needle,
            &mut next[one * NEXT..(one + 1) * NEXT],
            &mut seen[one * SEEN..(one + 1) * SEEN],
        );

        at += width as usize;
    }

    instrument(subject, held, &maps, &mut skips)?;

    let mut walk = Walk {
        needles,
        of,
        next,
        seen,
        widths,
        tail,
        lens,
        run: [0; NEEDLES],
        whole: [false; NEEDLES],
        through: 0,
        prev: 0,
    };

    let swept = sweep(subject, held, &maps, &skips, 0, |window, _, breaks| {
        walk.step(window, breaks);
    });

    let mut from = 0;

    for (one, &width) in of.iter().enumerate() {
        let width = width as usize;
        let step = density(&walk.next[one * NEXT..(one + 1) * NEXT]);

        let mut score = 0_u64;
        let mut widest = 0_u64;
        let mut closed = 0_u64;

        for (width, &count) in walk.widths[from..=from + width].iter().enumerate() {
            if count == 0 {
                continue;
            }

            closed += count;
            widest = width as u64;

            score += worth(width as u64, step, swept).saturating_mul(count);
        }

        let answer = &mut result[EACH * one..EACH * (one + 1)];

        answer[FOUND] = u64::from(walk.whole[one]);
        answer[SCORE] = score;
        answer[WIDEST] = widest;
        answer[RUNS] = closed;

        from += width + 1;
    }

    result[SWEPT] = swept;

    Ok(())
}

pub(crate) struct Walk<'a> {
    pub(crate) needles: &'a [u8],
    pub(crate) of: &'a [u64],
    pub(crate) next: &'a [u8],
    pub(crate) seen: &'a [u8],
    pub(crate) widths: &'a mut [u64],
    pub(crate) tail: &'a mut [u8],
    pub(crate) lens: &'a mut [u16],
    pub(crate) run: [usize; NEEDLES],
    pub(crate) whole: [bool; NEEDLES],
    pub(crate) through: usize,
    pub(crate) prev: u8,
}

impl Walk<'_> {
    pub(crate) fn step(&mut self, window: &[u8], breaks: bool) {
        for &byte in window {
            let (mut at, mut from) = (0, 0);

            for one in 0..self.of.len() {
                let width = self.of[one] as usize;
                let next = &self.next[one * NEXT..(one + 1) * NEXT];

                if self.run[one] > 0 && follows(next, self.prev, byte) {
                    self.run[one] += 1;
                } else {
                    self.whole[one] |= settle(
                        self.run[one],
                        self.tail,
                        self.through,
                        &self.needles[at..at + width],
                        &mut self.lens[..width],
                        &mut self.widths[from..=from + width],
                    );

                    self.run[one] =
                        usize::from(holds(&self.seen[one * SEEN..(one + 1) * SEEN], byte));
                }

                at += width;
                from += width + 1;
            }

            // Every byte, in or out of a run: the arithmetic that reads a
            // run back is then only about `through`, and not about where
            // the run was when it was written.
            self.tail[self.through % self.tail.len()] = byte;
            self.through += 1;
            self.prev = byte;
        }

        if breaks {
            let (mut at, mut from) = (0, 0);

            for one in 0..self.of.len() {
                let width = self.of[one] as usize;

                self.whole[one] |= settle(
                    self.run[one],
                    self.tail,
                    self.through,
                    &self.needles[at..at + width],
                    &mut self.lens[..width],
                    &mut self.widths[from..=from + width],
                );
                self.run[one] = 0;

                at += width;
                from += width + 1;
            }
        }
    }
}

/// What a run of that width is worth, in whole bits of surprise.
///
/// Each step past the first is worth `step`, and the whole run is charged
/// `log2` of the memory it was found in — three bytes of anything are in a
/// gigabyte of anything. Widths of nothing and of one are worth nothing by
/// construction: a run of one is a byte the secret happens to contain.
///
/// # What the charge buys
///
/// It makes the arithmetic independent of how much memory there is. A sweep
/// of twice the memory turns up twice as many accidental runs of a given
/// width, and charges each of them one more bit — so the number of accidental
/// runs worth `b` bits or more comes out the same either way. [`NOISE`] rests
/// on that, and so does comparing two photographs of processes that have
/// grown.
pub(crate) fn worth(width: u64, step: u64, swept: u64) -> u64 {
    if width < 2 {
        return 0;
    }

    // Saturating on both: a sweep cannot produce a run wide enough to overflow
    // either, but the arithmetic is a pure function of three numbers and being
    // total is what lets it be swept over rather than sampled.
    (width - 1).saturating_mul(step).saturating_sub(lg2(swept)) >> 10
}

/// What a score may rise by, between two photographs, and still be chance.
///
/// # Why a constant, when nothing else here is
///
/// Because [`worth`] has already taken the memory out. The chance of a run
/// worth `b` bits or more turning up by accident is `p · 2⁻ᵇ`, where `p` is
/// the chance a byte is in the secret at all — and neither the memory swept
/// nor the density of the secret appears in it. A score is already in units
/// that mean the same thing everywhere.
///
/// So the only thing left to choose is how rare a false alarm should be. At
/// `p ≤ 1`, sixteen bits is one photograph in sixty-five thousand.
///
/// A leak is nowhere near it: a whole copy of a thirty-two byte secret scores
/// a little over two hundred, and five bytes of one is already ten.
pub(crate) const NOISE: i128 = 16;

/// Which byte may follow which, and which are in the secret at all.
///
/// One bit each, so the secret is not in either table — only the shape of it
/// is, and the shape is what the sweep asks about.
pub(crate) fn table(secret: &[u8], next: &mut [u8], seen: &mut [u8]) {
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
pub(crate) fn follows(next: &[u8], from: u8, to: u8) -> bool {
    next[from as usize * 32 + (to >> 3) as usize] & (1 << (to & 7)) != 0
}

/// Whether the secret has that byte anywhere.
pub(crate) fn holds(seen: &[u8], byte: u8) -> bool {
    seen[(byte >> 3) as usize] & (1 << (byte & 7)) != 0
}

/// One more run of that width, and the widest one there is room to say.
pub(crate) fn close(run: usize, widths: &mut [u64]) {
    if run == 0 {
        return;
    }

    widths[run.min(MOST - 1)] += 1;
}

/// A run over: read back, tallied at the width it verifies to, and whether
/// that width was the whole secret.
pub(crate) fn settle(
    run: usize,
    tail: &[u8],
    through: usize,
    secret: &[u8],
    lens: &mut [u16],
    widths: &mut [u64],
) -> bool {
    let real = piece(run, tail, through, secret, lens);

    close(real, widths);

    real == secret.len()
}

/// The widest stretch of the secret inside a run, read back out of the ring.
///
/// A run of one is a byte the secret has and a run of two is a pair it has,
/// so up to two the run is a stretch of the secret by construction. Past that
/// it is a walk through the secret's pairs, and a walk can turn where the
/// secret does not.
///
/// `through` is how many bytes have gone through the ring, the run's last one
/// included. Only the last `tail.len()` of them are still there, which is as
/// far back as a stretch of the secret can reach: anything a wider run held
/// before that is not read.
///
/// One byte repeated is answered without the scan. It is the common shape of
/// a wide run — a page of one value, a vector register broadcast — and the
/// answer is how many of that byte the secret has in a row.
pub(crate) fn piece(
    run: usize,
    tail: &[u8],
    through: usize,
    secret: &[u8],
    lens: &mut [u16],
) -> usize {
    if run <= 2 {
        return run;
    }

    let width = run.min(tail.len());
    let byte = |k: usize| tail[(through - width + k) % tail.len()];
    let first = byte(0);

    if (1..width).all(|k| byte(k) == first) {
        return stretch(secret, first).min(width);
    }

    // `lens[j]` is how far a stretch of the secret ending at `j` matches the
    // run ending at the byte just read. Walked from the top so that each
    // entry is read before it is written over.
    lens.fill(0);

    let mut widest = 0;

    for k in 0..width {
        let byte = byte(k);

        for j in (0..secret.len()).rev() {
            lens[j] = if secret[j] == byte {
                if j == 0 { 1 } else { lens[j - 1] + 1 }
            } else {
                0
            };

            widest = widest.max(usize::from(lens[j]));
        }

        if widest == secret.len() {
            break;
        }
    }

    widest
}

/// How many of that byte the secret has in a row, at most.
pub(crate) fn stretch(secret: &[u8], byte: u8) -> usize {
    let mut longest = 0;
    let mut now = 0;

    for &each in secret {
        now = if each == byte { now + 1 } else { 0 };
        longest = longest.max(now);
    }

    longest
}

/// What one step of a run is worth, in bits, to ten binary places.
///
/// The table's density is what makes a step surprising: with one successor per
/// byte a step is a byte, worth eight bits, and with thirteen of them it is
/// worth `log2(256 / 13)`, a little over four. Dividing by the number of bytes
/// that have any successor at all is what keeps a short secret from being
/// judged as if it were a dense one.
pub(crate) fn density(next: &[u8]) -> u64 {
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
pub(crate) fn lg2(of: u64) -> u64 {
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
