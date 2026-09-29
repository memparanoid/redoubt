// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::analysis::report::{QUIET, Report};
use crate::analysis::score::NOISE;
use crate::verdicts::{is_found, leaves_no_copy, leaves_nothing};

const CLEAN: Report = Report {
    found: false,
    score: 100,
    swept: 1 << 21,
    widest: 3,
    runs: 1000,
};

// ============================================================================
// is_found
// ============================================================================

#[test]
#[should_panic(expected = "the sweep does not reach")]
fn test_is_found_refuses_a_photograph_without_the_whole_secret() {
    is_found(
        &Report {
            widest: 31,
            ..CLEAN
        },
        "a planting",
    );
}

#[test]
fn test_is_found_accepts_a_photograph_with_the_whole_secret() {
    is_found(
        &Report {
            found: true,
            widest: 32,
            ..CLEAN
        },
        "a planting",
    );
}

// ============================================================================
// leaves_no_copy
// ============================================================================

#[test]
#[should_panic(expected = "the whole secret was left behind")]
fn test_leaves_no_copy_refuses_the_whole_secret() {
    leaves_no_copy(
        &Report {
            found: true,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
#[should_panic(expected = "bytes of the secret was left behind")]
fn test_leaves_no_copy_refuses_a_run_one_past_quiet() {
    leaves_no_copy(
        &Report {
            widest: QUIET + 1,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
fn test_leaves_no_copy_accepts_a_run_of_exactly_quiet() {
    leaves_no_copy(
        &Report {
            widest: QUIET,
            ..CLEAN
        },
        "an operation",
    );
}

// ============================================================================
// leaves_nothing
// ============================================================================

#[test]
#[should_panic(expected = "the whole secret was left behind")]
fn test_leaves_nothing_refuses_the_whole_secret() {
    leaves_nothing(
        &CLEAN,
        &Report {
            found: true,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
#[should_panic(expected = "bytes of the secret was left behind")]
fn test_leaves_nothing_refuses_a_run_one_past_quiet() {
    leaves_nothing(
        &CLEAN,
        &Report {
            widest: QUIET + 1,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
#[should_panic(expected = "moved the score past chance")]
fn test_leaves_nothing_refuses_a_score_one_past_noise() {
    leaves_nothing(
        &CLEAN,
        &Report {
            score: CLEAN.score + NOISE as u64 + 1,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
fn test_leaves_nothing_accepts_a_score_that_rose_by_exactly_noise() {
    leaves_nothing(
        &CLEAN,
        &Report {
            score: CLEAN.score + NOISE as u64,
            widest: QUIET,
            ..CLEAN
        },
        "an operation",
    );
}

#[test]
fn test_leaves_nothing_accepts_a_score_that_fell() {
    leaves_nothing(
        &Report {
            score: 5000,
            ..CLEAN
        },
        &CLEAN,
        "an operation",
    );
}
