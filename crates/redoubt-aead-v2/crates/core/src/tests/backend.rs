// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the comparison answers, from both implementations.
//!
//! What it leaves behind is measured in `asm`, against the routine's own
//! verifier. Nothing here is a claim about timing: a test that measured the
//! clock would be measuring this machine under this load, and the property the
//! assembly is written for is that the instructions taken do not depend on the
//! bytes — which is read, not timed.

use std::vec::Vec;

use rstest::rstest;

use crate::Backend;
use crate::backend::{HAS_ASM, constant_time_eq, constant_time_eq_with_backend};

/// A tag's width, which is what every caller of this compares.
const TAG_SIZE: usize = 16;

/// The precondition every case below rests on, which is why it is first.
///
/// The two backends are the same code where the target has no assembly, and a
/// pair of cases that found them agreeing there would have proved nothing
/// about either — while reading as though it had proved it twice.
#[test]
#[expect(
    clippy::assertions_on_constants,
    reason = "a constant is what it asks about: whether this build has the assembly at all"
)]
fn test_this_target_has_the_assembly() {
    assert!(
        HAS_ASM,
        "the cases below name two backends and this target has one"
    );
}

// === === === === === === === === === ===
// constant_time_eq
// === === === === === === === === === ===

/// The exported one, which is the only one anything outside this crate can
/// reach and therefore the only one a consumer ever runs.
///
/// Every other test here names a backend. This one takes the default, so that
/// resolving it is not the one step nothing covers.
#[test]
fn test_constant_time_eq_answers_from_the_default_backend() {
    let a = [0x5au8; TAG_SIZE];
    let mut b = a;

    assert!(constant_time_eq(&a, &b));

    b[TAG_SIZE - 1] ^= 1;

    assert!(!constant_time_eq(&a, &b));
}

// === === === === === === === === === ===
// constant_time_eq_with_backend
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_with_backend_reports_runs_of_different_length(#[case] backend: Backend) {
    // Neither run is read, so the shorter one being a prefix of the longer
    // changes nothing: the lengths already differ and that is public.
    let short = [0x11u8; TAG_SIZE];
    let long = [0x11u8; TAG_SIZE + 1];

    assert!(!constant_time_eq_with_backend(backend, &short, &long));
    assert!(!constant_time_eq_with_backend(backend, &long, &short));
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_with_backend_reports_two_empty_runs_equal(#[case] backend: Backend) {
    // The loop never runs, and the accumulator it would have folded into is
    // the answer. Which is the one length where "equal" comes from nothing
    // having been compared rather than from everything having matched.
    assert!(constant_time_eq_with_backend(backend, &[], &[]));
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_with_backend_sees_a_difference_at_every_position(
    #[case] backend: Backend,
) {
    // One byte at a time, over the whole width. A fold that stopped early, or
    // one that read a word at a time and dropped the tail, passes a test that
    // only ever differs in the middle.
    let a: [u8; TAG_SIZE] = core::array::from_fn(|at| at as u8);

    for at in 0..TAG_SIZE {
        let mut b = a;
        b[at] ^= 0x80;

        assert!(
            !constant_time_eq_with_backend(backend, &a, &b),
            "a difference at byte {at} reads as equal"
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_with_backend_sees_every_bit_of_a_byte(#[case] backend: Backend) {
    // The other axis. A fold that or-ed the wrong width, or masked, answers
    // correctly for the high bit above and not for the one below it.
    let a = [0u8; TAG_SIZE];

    for bit in 0..8 {
        let mut b = a;
        b[0] = 1 << bit;

        assert!(
            !constant_time_eq_with_backend(backend, &a, &b),
            "bit {bit} of the first byte reads as equal"
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_with_backend_reports_equal_runs_equal(#[case] backend: Backend) {
    // The positive, and the reason the four above mean anything: a comparison
    // that answered false whatever it was handed would pass every one of them.
    //
    // Two allocations and not one slice handed over twice: the same slice as
    // both arguments is one address, and an implementation that compared
    // pointers would answer correctly without reading a byte.
    for length in [0usize, 1, 15, 16, 17, 31, 32, 64] {
        let a: Vec<u8> = (0..length).map(|at| (at as u8) ^ 0x5a).collect();
        let b = a.clone();

        assert!(
            constant_time_eq_with_backend(backend, &a, &b),
            "two runs of {length} equal bytes read as different"
        );
    }
}
