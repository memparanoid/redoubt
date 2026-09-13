// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The weighing, on bytes alone.
//!
//! Nothing here forks, allocates or reads another process. What is asserted is
//! the arithmetic that decides what a run is worth — which used to be
//! reachable only by photographing a process, and so was never asserted at
//! all.

use crate::analysis::score::{close, density, follows, holds, lg2, table};
use crate::analysis::state::MOST;

/// Room for one table of successors and one of bytes that appear.
fn tables() -> (Vec<u8>, Vec<u8>) {
    (vec![0_u8; 256 * 32], vec![0_u8; 32])
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
