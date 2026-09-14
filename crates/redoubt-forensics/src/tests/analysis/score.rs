// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The weighing, on bytes alone.
//!
//! Nothing here forks, allocates or reads another process. What is asserted is
//! the arithmetic that decides what a run is worth — which used to be
//! reachable only by photographing a process, and so was never asserted at
//! all.
//!
//! # The oracle
//!
//! Most of what is here is a pure function with no external observable, so
//! the only oracle available is a second formulation — and a second
//! formulation written by reading the first is not one. Numbers copied out of
//! the implementation would be the implementation agreeing with itself.
//!
//! So the oracle is the definition the arithmetic stands for. A run of `w`
//! bytes is a stretch the secret allowed `w - 1` times in a row; if each step
//! is allowed with probability `p`, that happens by chance at a given place
//! with probability `p^(w-1)`, and a sweep of `n` bytes offers `n` places. The
//! surprise of finding one is therefore `-(w - 1)·log2(p) - log2(n)` bits.
//! [`worth`] is that number, and `std`'s `log2` computes the right-hand side
//! without reference to ours.

use proptest::prelude::*;

use crate::analysis::score::{
    NOISE, close, density, follows, holds, lg2, piece, settle, stretch, table, worth,
};
use crate::analysis::state::MOST;

/// Room for one table of successors and one of bytes that appear.
fn tables() -> (Vec<u8>, Vec<u8>) {
    (vec![0_u8; 256 * 32], vec![0_u8; 32])
}

/// Thirty-two distinct bytes, so that a stretch of it is a stretch of it and
/// not a walk that happened to agree.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A ring of `MOST` bytes with `run` written so that it ends after `through`
/// bytes have gone by, the way the sweep leaves it.
fn ring(run: &[u8], through: usize) -> Vec<u8> {
    let mut tail = vec![0_u8; MOST];

    for (k, &byte) in run.iter().enumerate() {
        tail[(through - run.len() + k) % MOST] = byte;
    }

    tail
}

/// Scratch for verifying against a secret that long.
fn lens(of: usize) -> Vec<u16> {
    vec![0_u16; of]
}

/// What one step costs for a short secret whose bytes are all different: each
/// byte has one successor out of 256, so a whole byte of surprise.
const SPARSE: u64 = 8 * 1024;

/// A few megabytes, which is what a small process sweeps.
const SWEPT: u64 = 1 << 21;

/// The widest run the tally can hold, which is the widest a sweep can report.
const WIDEST: u64 = MOST as u64;

/// The most a step can cost.
///
/// [`density`] answers `8192 + log2(nodes) − log2(edges)` in ten binary
/// places, and a byte with a successor has at least one, so `edges ≥ nodes`
/// and the answer never passes a whole byte. That is the top of the range
/// worth generating; past it is arithmetic nothing can ask for.
const STEEPEST: u64 = 8 * 1024;

/// As much memory as a process is going to have, generously.
const MEMORY: u64 = 1 << 48;

/// The surprise a run of that width stands for, in bits, worked out from what
/// a run *is* rather than from how it is scored.
///
/// `p = 2^(-step/1024)` is not a reading of the implementation either: `step`
/// is defined as `log2(256 / t)` in ten binary places, so `2^(-step/1024)` is
/// `t / 256`, which is the chance a byte of ordinary memory continues a run.
#[allow(clippy::cast_precision_loss)]
fn surprise(width: u64, step: u64, swept: u64) -> f64 {
    (width - 1) as f64 * step as f64 / 1024.0 - (swept as f64).log2()
}

/// How many runs worth `bits` or more a sweep is expected to throw up by
/// chance.
///
/// Every position is treated as able to start a run, which no real secret
/// manages — a byte starts one only if the secret contains it — so this is an
/// upper bound, which is the side worth bounding.
#[allow(clippy::cast_precision_loss)]
fn by_chance(bits: u64, step: u64, swept: u64) -> f64 {
    let extending = 2_f64.powf(-(step as f64) / 1024.0);

    // The narrowest run that clears the bar. Everything wider is rarer, and
    // the widths in between are already counted by it.
    for width in 2..=(MOST as u64) {
        if worth(width, step, swept) >= bits {
            return swept as f64 * extending.powi(width as i32 - 1);
        }
    }

    0.0
}

// ============================================================================
// worth
// ============================================================================

/// A run of no bytes, and a run of one, are worth nothing.
///
/// A single byte the secret happens to contain is not a stretch of it: with
/// thirty-two distinct bytes, one byte of ordinary memory is one of them once
/// every eight bytes.
#[test]
fn test_worth_is_nothing_for_a_run_too_short_to_be_one() {
    assert_eq!(worth(0, SPARSE, SWEPT), 0);
    assert_eq!(worth(1, SPARSE, SWEPT), 0);
}

/// When the memory outweighs the run, the run is worth nothing — not a very
/// large number from an underflow.
#[test]
fn test_worth_is_nothing_when_the_memory_outweighs_the_run() {
    assert_eq!(worth(2, SPARSE, u64::MAX), 0);
    assert_eq!(worth(3, 1, u64::MAX), 0);
}

proptest! {
    /// Every extra byte is another step the secret had to allow, so a wider
    /// run can never say less.
    #[test]
    fn test_worth_never_falls_as_the_run_widens(
        width in 0..WIDEST,
        step in 0..=STEEPEST,
        swept in 1..=MEMORY,
    ) {
        prop_assert!(worth(width + 1, step, swept) >= worth(width, step, swept));
    }

    /// A sparser secret makes each step more of a surprise, so the same run
    /// says more.
    #[test]
    fn test_worth_never_falls_as_the_secret_gets_sparser(
        width in 0..=WIDEST,
        step in 0..STEEPEST,
        swept in 1..=MEMORY,
    ) {
        prop_assert!(worth(width, step + 1, swept) >= worth(width, step, swept));
    }

    /// More memory is more places for a run to turn up in, so the same run
    /// says less.
    #[test]
    fn test_worth_never_rises_as_more_memory_is_swept(
        width in 0..=WIDEST,
        step in 0..=STEEPEST,
        shift in 1_u32..62,
    ) {
        prop_assert!(worth(width, step, 1 << (shift + 1)) <= worth(width, step, 1 << shift));
    }

    /// Each byte past the first adds one step's worth, which is what a step
    /// is.
    ///
    /// Whole bits, so the fraction each truncation drops shows up as a
    /// difference of one either way.
    #[test]
    fn test_worth_adds_one_step_per_byte_past_the_first(
        width in 2..WIDEST,
        step in 1024..=STEEPEST,
        swept in 1..=MEMORY,
    ) {
        // Only where both widths are past the floor: below it they are both
        // nothing, and nothing minus nothing says nothing about a step.
        prop_assume!(worth(width, step, swept) > 0);

        let grew = worth(width + 1, step, swept) - worth(width, step, swept);

        prop_assert!(
            grew.abs_diff(step / 1024) <= 1,
            "a step of {step} is worth {} a byte, and width {width} grew by {grew}",
            step / 1024,
        );
    }

    /// What it reports is the surprise the run stands for.
    ///
    /// The right-hand side is the definition, computed with `std`'s `log2`.
    /// They agree to within what whole bits can carry: the arithmetic drops
    /// the fraction, and [`lg2`] reads a shade under the true logarithm.
    #[test]
    fn test_worth_agrees_with_the_surprise_a_run_stands_for(
        width in 2..=WIDEST,
        step in 0..=STEEPEST,
        swept in 1..=MEMORY,
    ) {
        let want = surprise(width, step, swept);
        let got = worth(width, step, swept);

        if want <= 0.0 {
            prop_assert_eq!(got, 0);

            return Ok(());
        }

        #[allow(clippy::cast_precision_loss)]
        let got = got as f64;

        prop_assert!(got <= want + 0.1, "said {got}, stands for {want}");
        prop_assert!(got >= want - 1.1, "said {got}, stands for {want}");
    }

    /// And where it disagrees it is always low.
    ///
    /// A score that misses a leak by a hair, never one that invents a leak
    /// out of rounding.
    #[test]
    fn test_worth_never_overstates_a_run(
        width in 0..=WIDEST,
        step in 0..=STEEPEST,
        swept in 1..=MEMORY,
    ) {
        #[allow(clippy::cast_precision_loss)]
        let got = worth(width, step, swept) as f64;

        prop_assert!(got <= surprise(width.max(1), step, swept).max(0.0) + 0.1);
    }
}

/// Nothing in the whole range of three `u64`s overflows or panics.
#[test]
fn test_worth_answers_for_anything_three_numbers_can_be() {
    for width in [0_u64, 1, 2, MOST as u64, u32::MAX.into(), u64::MAX] {
        for step in [0_u64, 1, SPARSE, u32::MAX.into(), u64::MAX] {
            for swept in [0_u64, 1, SWEPT, u64::MAX] {
                let _ = worth(width, step, swept);
            }
        }
    }
}

/// A sweep of no memory has nothing to charge against, so the narrowest run
/// there is already counts.
#[test]
fn test_worth_charges_nothing_against_no_memory() {
    assert_eq!(worth(2, SPARSE, 0), SPARSE >> 10);
}

/// A secret whose bytes say nothing about each other makes every run worth
/// nothing, however wide.
#[test]
fn test_worth_is_nothing_when_a_step_says_nothing() {
    for width in [2_u64, 32, 1024] {
        assert_eq!(worth(width, 0, SWEPT), 0);
    }
}

// ============================================================================
// NOISE
// ============================================================================

proptest! {
    /// Chance clears the ceiling no more often than the allowance, for every
    /// amount of memory and every secret.
    ///
    /// This is the whole reason the ceiling can be a constant. A run worth
    /// `b` bits or more turns up by chance at most `2⁻ᵇ` times per sweep —
    /// the memory cancels, because [`worth`] charges each run exactly the
    /// `log2` of it that makes the count grow. The factor of two is the slack
    /// a geometric tail and two roundings need.
    #[test]
    fn test_chance_clears_the_ceiling_no_more_than_the_allowance(
        step in 1024..=STEEPEST,
        shift in 8_u32..48,
    ) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ceiling = NOISE as u64;

        #[allow(clippy::cast_precision_loss)]
        let allowed = 2_f64.powi(1 - NOISE as i32);

        let chance = by_chance(ceiling, step, 1 << shift);

        prop_assert!(
            chance <= allowed,
            "a step of {step} over 2^{shift} bytes clears {ceiling} bits {chance} times, \
             and {allowed} is the allowance",
        );
    }

    /// A run of the secret's own width is far past the ceiling, whatever the
    /// secret and whatever the memory.
    ///
    /// The other end of the same bound: a ceiling that is only above the
    /// noise is no use if a whole copy is not well above it.
    #[test]
    fn test_a_whole_secret_is_far_past_the_ceiling(
        of in 16..=4096_u64,
        shift in 8_u32..48,
    ) {
        // What `density` makes of a secret that long, near enough: each byte
        // has about `of / 256` successors once the secret is longer than the
        // alphabet, and one while it is shorter.
        let successors = (of / 256).max(1);
        let step = SPARSE - lg2(successors);

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ceiling = NOISE as u64;

        let got = worth(of, step, 1 << shift);

        prop_assert!(
            got >= ceiling * 4,
            "a whole secret of {of} bytes at step {step} over 2^{shift} bytes is worth {got}",
        );
    }

    /// And two bytes of it are not, whatever the secret and whatever the
    /// memory.
    #[test]
    fn test_two_bytes_of_a_secret_never_clear_the_ceiling(
        step in 0..=STEEPEST,
        shift in 8_u32..48,
    ) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ceiling = NOISE as u64;

        let got = worth(2, step, 1 << shift);

        prop_assert!(got < ceiling, "two bytes at step {step} over 2^{shift} are worth {got}");
    }
}

/// The ceiling and a real secret's own density agree: a whole copy of a
/// thirty-two byte secret clears it and a pair of its bytes does not.
///
/// The `step` here is not a number chosen for the test — it is what
/// [`density`] makes of a table built from the secret, so this is the two
/// halves of the arithmetic meeting.
#[test]
fn test_the_ceiling_reads_a_real_secret_the_way_it_should() {
    const SECRET: [u8; 32] = [
        0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE,
        0x71, 0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF,
        0x13, 0xCA,
    ];

    let (mut next, mut seen) = tables();

    table(&SECRET, &mut next, &mut seen);

    let step = density(&next);

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ceiling = NOISE as u64;

    assert!(
        worth(SECRET.len() as u64, step, SWEPT) > ceiling,
        "a whole copy is not evidence"
    );
    assert!(worth(2, step, SWEPT) < ceiling, "two bytes are evidence");
}

// ============================================================================
// table, follows, holds
// ============================================================================

/// Every pair that is in the secret is in the table.
#[test]
fn test_follows_accepts_every_pair_the_secret_has() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);

    assert!(follows(&next, b'a', b'b'));
    assert!(follows(&next, b'b', b'c'));
    assert!(follows(&next, b'c', b'd'));
}

/// And a pair it does not have is not, which is what closes a run.
#[test]
fn test_follows_refuses_a_pair_the_secret_does_not_have() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);

    assert!(!follows(&next, b'a', b'c'));
    assert!(!follows(&next, b'd', b'a'));
}

/// A byte with two different successors keeps both. This is the case a table
/// of one successor per byte would get wrong, and getting it wrong means
/// closing a run that should have carried on.
#[test]
fn test_follows_keeps_every_successor_a_byte_has() {
    let (mut next, mut seen) = tables();

    table(b"abac", &mut next, &mut seen);

    assert!(follows(&next, b'a', b'b'));
    assert!(follows(&next, b'a', b'c'));
}

/// The table is about pairs, not places: the same pair anywhere in the secret
/// is the same bit.
#[test]
fn test_table_is_built_fresh_each_time() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);
    table(b"wxyz", &mut next, &mut seen);

    assert!(
        !follows(&next, b'a', b'b'),
        "the first secret was still in the table"
    );
    assert!(follows(&next, b'w', b'x'));
}

/// Which bytes are in the secret at all, which is what starts a run.
#[test]
fn test_holds_answers_for_the_bytes_the_secret_has() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);

    assert!(holds(&seen, b'a'));
    assert!(holds(&seen, b'd'));
    assert!(!holds(&seen, b'e'));
    assert!(!holds(&seen, 0));
}

/// A secret of one byte has that byte and no pairs at all, so nothing can
/// extend and every run is one wide.
#[test]
fn test_a_single_byte_secret_has_no_pairs() {
    let (mut next, mut seen) = tables();

    table(b"a", &mut next, &mut seen);

    assert!(holds(&seen, b'a'));
    assert!(!follows(&next, b'a', b'a'));
}

// ============================================================================
// close
// ============================================================================

/// A run of nothing is not a run.
#[test]
fn test_close_tallies_nothing_for_a_run_of_zero() {
    let mut widths = vec![0_u64; MOST];

    close(0, &mut widths);

    assert!(widths.iter().all(|count| *count == 0));
}

#[test]
fn test_close_tallies_a_run_at_its_width() {
    let mut widths = vec![0_u64; MOST];

    close(5, &mut widths);
    close(5, &mut widths);

    assert_eq!(widths[5], 2);
}

/// A run wider than there is room to say lands in the last slot rather than
/// out of bounds. A sweep that found one this wide has a much larger problem
/// than the tally being off.
#[test]
fn test_close_puts_a_run_wider_than_the_tally_in_the_last_slot() {
    let mut widths = vec![0_u64; MOST];

    close(MOST * 4, &mut widths);

    assert_eq!(widths[MOST - 1], 1);
}

// ============================================================================
// settle
// ============================================================================

/// What is tallied is the width the run reads back to, not the width it
/// walked: sixteen of one byte, with the secret holding two of it, is one
/// more run of two.
#[test]
fn test_settle_tallies_the_width_the_run_reads_back_to() {
    let secret = b"a88b";
    let run = [b'8'; 16];
    let tail = ring(&run, run.len());
    let mut widths = vec![0_u64; MOST];

    let whole = settle(
        run.len(),
        &tail,
        run.len(),
        secret,
        &mut lens(secret.len()),
        &mut widths,
    );

    assert!(!whole);
    assert_eq!(widths[2], 1);
    assert_eq!(widths[16], 0);
}

/// A run that reads back as wide as the secret is the secret.
#[test]
fn test_settle_returns_true_for_a_run_that_is_the_whole_secret() {
    let tail = ring(&SECRET, SECRET.len());
    let mut widths = vec![0_u64; MOST];

    let whole = settle(
        SECRET.len(),
        &tail,
        SECRET.len(),
        &SECRET,
        &mut lens(SECRET.len()),
        &mut widths,
    );

    assert!(whole);
    assert_eq!(widths[SECRET.len()], 1);
}

// ============================================================================
// piece
// ============================================================================

/// One byte the secret has, or a pair it has, is a stretch of it by the way a
/// run starts and extends, so nothing is read back.
#[test]
fn test_piece_returns_the_width_for_a_run_of_two_or_less() {
    let tail = vec![0_u8; MOST];

    for run in 0..=2 {
        assert_eq!(
            piece(run, &tail, MOST, &SECRET, &mut lens(SECRET.len())),
            run
        );
    }
}

/// One byte repeated is worth as many of it as the secret has in a row, and
/// no more than the run has.
#[test]
fn test_piece_returns_the_stretch_for_a_run_of_one_repeated_byte() {
    let run = [b'8'; 16];
    let tail = ring(&run, run.len());

    assert_eq!(piece(16, &tail, 16, b"a88b", &mut lens(4)), 2);
    assert_eq!(piece(16, &tail, 16, b"a888b", &mut lens(5)), 3);
    assert_eq!(piece(3, &tail, 16, b"88888", &mut lens(5)), 3);
}

/// A walk that turns where the secret does not is worth the widest stretch
/// of the secret in it: `abcab` walks `abcad`'s pairs and holds `abca`.
#[test]
fn test_piece_returns_the_widest_stretch_of_the_secret_a_walk_holds() {
    let run = b"abcab";
    let tail = ring(run, run.len());

    assert_eq!(
        piece(run.len(), &tail, run.len(), b"abcad", &mut lens(5)),
        4
    );
}

/// A cycle through several pairs walks as far as memory repeats it. `the`
/// twice in the sentence, once after a space, is the cycle `t h e ␣`, and a
/// page of `the the the` walks it to its end. The sentence holds ` the ` and
/// no more.
#[test]
fn test_piece_returns_the_widest_stretch_for_a_walk_around_a_cycle_of_words() {
    let secret = b"the quick brown fox jumps over the lazy dog";
    let run = b"the the the the the";
    let tail = ring(run, run.len());

    assert_eq!(
        piece(run.len(), &tail, run.len(), secret, &mut lens(secret.len())),
        " the ".len()
    );
}

/// A run that is a stretch of the secret is worth its whole width.
#[test]
fn test_piece_returns_the_width_of_a_run_that_is_a_stretch_of_the_secret() {
    let run = &SECRET[8..24];
    let tail = ring(run, run.len());

    assert_eq!(
        piece(
            run.len(),
            &tail,
            run.len(),
            &SECRET,
            &mut lens(SECRET.len())
        ),
        16
    );
}

/// The ring is a ring: a run written across its end reads back whole.
#[test]
fn test_piece_reads_a_run_that_wraps_around_the_ring() {
    let run = &SECRET[8..24];
    let through = MOST + 5;
    let tail = ring(run, through);

    assert_eq!(
        piece(run.len(), &tail, through, &SECRET, &mut lens(SECRET.len())),
        16
    );
}

/// Only the last `MOST` bytes of a wider run are there to read. The six that
/// begin this one are past the ring, and what is left is the three the
/// alternation holds.
#[test]
fn test_piece_reads_only_the_last_most_bytes_of_a_wider_run() {
    let secret = b"abcdaba";
    let mut run = b"abcdab".to_vec();

    while run.len() < MOST + 6 {
        run.push(if run.len().is_multiple_of(2) {
            b'a'
        } else {
            b'b'
        });
    }

    let tail = ring(&run, run.len());

    assert_eq!(
        piece(run.len(), &tail, run.len(), secret, &mut lens(secret.len())),
        3
    );
}

/// The whole secret reads back as the whole secret.
#[test]
fn test_piece_returns_the_whole_width_for_a_run_that_is_the_secret() {
    let tail = ring(&SECRET, SECRET.len());

    assert_eq!(
        piece(
            SECRET.len(),
            &tail,
            SECRET.len(),
            &SECRET,
            &mut lens(SECRET.len())
        ),
        SECRET.len()
    );
}

// ============================================================================
// stretch
// ============================================================================

#[test]
fn test_stretch_returns_nothing_for_a_byte_the_secret_lacks() {
    assert_eq!(stretch(b"a88b888c", b'z'), 0);
}

/// The longest of the stretches, not the first and not their sum.
#[test]
fn test_stretch_returns_the_longest_stretch_of_a_byte() {
    assert_eq!(stretch(b"a88b888c", b'8'), 3);
    assert_eq!(stretch(b"a88b888c", b'a'), 1);
}

// ============================================================================
// density
// ============================================================================

/// A table nothing was built into cannot say anything about a step, so a step
/// is worth a whole byte — the most it can ever be worth, which is the safe
/// direction to be wrong in.
#[test]
fn test_density_is_a_whole_byte_for_an_empty_table() {
    let (next, _) = tables();

    assert_eq!(density(&next), 8 * 1024);
}

/// One successor per byte is one byte of surprise per step.
#[test]
fn test_density_is_a_whole_byte_when_every_byte_has_one_successor() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);

    assert_eq!(density(&next), 8 * 1024);
}

/// More successors per byte is less surprise per step, which is the whole
/// reason the floor moves by itself: a long secret has a denser table, and its
/// runs have to be longer before they mean anything.
#[test]
fn test_density_falls_as_a_byte_gains_successors() {
    let (mut next, mut seen) = tables();

    table(b"abcd", &mut next, &mut seen);

    let sparse = density(&next);

    table(b"abacadaeafagah", &mut next, &mut seen);

    let dense = density(&next);

    assert!(
        dense < sparse,
        "a denser table was not worth less: {dense} against {sparse}"
    );
}
// ============================================================================
// lg2
// ============================================================================

/// Exact on the powers of two, which is where it has to be exact: those are
/// the anchors the straight line between them is drawn from.
#[test]
fn test_lg2_is_exact_on_the_powers_of_two() {
    assert_eq!(lg2(1), 0);
    assert_eq!(lg2(2), 1024);
    assert_eq!(lg2(256), 8 * 1024);
    assert_eq!(lg2(1 << 30), 30 * 1024);
}

/// Zero has no logarithm and answering one would be worse than answering
/// nothing, so it is floored.
#[test]
fn test_lg2_answers_zero_for_zero() {
    assert_eq!(lg2(0), 0);
}

/// Never falls, which is the only property the score actually leans on: more
/// memory swept can only raise the floor a run has to clear.
#[test]
fn test_lg2_never_falls() {
    let mut last = 0;

    for of in 1..4096_u64 {
        let now = lg2(of);

        assert!(now >= last, "lg2({of}) fell to {now} from {last}");

        last = now;
    }
}

/// And stays within a tenth of a bit of the real thing, which is what makes it
/// usable as a floor: the error is far smaller than a run being one byte
/// wider.
#[test]
fn test_lg2_stays_within_a_tenth_of_a_bit() {
    for of in [3_u64, 7, 100, 1000, 65_535, 1 << 40] {
        #[allow(clippy::cast_precision_loss)]
        let real = (of as f64).log2() * 1024.0;
        let ours = lg2(of) as f64;

        assert!(
            (real - ours).abs() < 103.0,
            "lg2({of}) was {ours}, not {real}"
        );
    }
}
