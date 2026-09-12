// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a caller concludes from a count of zero is only as good as this file,
//! so both directions are asserted here against a needle whose whereabouts are
//! known.

use crate::memory::{region, within};
use crate::score::{occurrences, occurrences_reversed};

/// A needle that is not a run of one byte and is not a palindrome: the first
/// would match at every offset inside itself, the second would read the same
/// in both directions and make the two counts agree for the wrong reason.
const NEEDLE: [u8; 8] = [0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88];

// ============================================================================
// occurrences
// ============================================================================

/// Something the test is holding is somewhere: the value below is in this
/// process, so a scanner that answers zero is not reading memory at all.
#[test]
fn test_occurrences_finds_what_the_process_is_holding() {
    let held = NEEDLE.to_vec();

    assert!(occurrences(&held) > 0);
}

// ============================================================================
// occurrences_reversed
// ============================================================================

/// The needle is held forwards, so backwards it is absent — and it stays
/// absent because asking never writes it down. This is the whole basis of
/// every zero a caller asserts.
#[test]
fn test_occurrences_reversed_finds_nothing_for_a_needle_held_forwards() {
    let held = NEEDLE.to_vec();

    assert_eq!(occurrences_reversed(&held), 0);
}

/// The same value twice, one of them reversed, and the reversed one finds the
/// other.
///
/// This is the shape every count of zero leans on, asserted here where the
/// whereabouts of both copies are known: a caller reverses what it was handed
/// and searches with it, and what it is really asking is whether a second copy
/// — one nobody reversed — is anywhere. Here there is one on purpose, so the
/// search has to find it; a reversed search that always answered zero would
/// pass every one of those tests without looking.
///
/// The unreversed copy is on the heap and not the constant it came from: only
/// writable mappings are read, and a constant lives where nothing can write.
#[test]
fn test_occurrences_reversed_finds_the_copy_that_was_not_reversed() {
    // This is the copy the search is looking for, and being bound is not
    // enough to have one: nothing reads it, so an optimizing build is free to
    // never make it. `black_box` is what says it was observed, which is what
    // forces it to exist somewhere to observe.
    let _held = core::hint::black_box(NEEDLE.to_vec());
    let mut needle = NEEDLE.to_vec();

    needle.reverse();

    assert!(occurrences_reversed(&needle) > 0);
}

// ============================================================================
// region
// ============================================================================

/// The bounds of a mapping that can be written to. Writable and not merely
/// readable, because what is left behind is left behind by writing.
#[test]
fn test_region_returns_the_bounds_of_a_writable_mapping() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0"),
        Some((0x7f8e_1c00_0000, 0x7f8e_1c02_1000)),
    );
}

/// A mapping nothing can write to holds only what a compiler put there, so it
/// is skipped rather than swept.
#[test]
fn test_region_returns_nothing_for_a_mapping_that_cannot_be_written() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 r-xp 00000000 00:00 0 [vdso]"),
        None,
    );
}

#[test]
fn test_region_returns_nothing_for_a_line_that_is_not_one() {
    assert_eq!(region(b""), None);
}

// ============================================================================
// within
// ============================================================================

/// Every occurrence and not the first: a secret in two places has to read as
/// two.
#[test]
fn test_within_counts_every_occurrence() {
    assert_eq!(within(b"--ab--ab--", b"ab", false), 2);
}

#[test]
fn test_within_counts_a_needle_read_backwards() {
    assert_eq!(within(b"--ba--", b"ab", true), 1);
}

/// A window shorter than the needle holds none of it, which is what the last
/// read of a mapping looks like.
#[test]
fn test_within_counts_nothing_in_less_than_a_needle() {
    assert_eq!(within(b"a", b"ab", false), 0);
}
