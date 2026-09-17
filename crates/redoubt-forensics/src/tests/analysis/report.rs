// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What two photographs say between them.

use crate::analysis::report::Report;
use crate::analysis::score::NOISE;

/// A photograph of a process that found nothing.
fn quiet() -> Report {
    Report {
        found: false,
        score: 0,
        swept: 1 << 21,
        widest: 0,
        runs: 0,
    }
}

// ============================================================================
// Report::against
// ============================================================================

/// Each number is the later photograph's less the earlier one's.
#[test]
fn test_against_returns_the_difference_between_two_photographs() {
    let before = Report {
        found: false,
        score: 10,
        swept: 100,
        widest: 2,
        runs: 7,
    };
    let after = Report {
        found: false,
        score: 40,
        swept: 160,
        widest: 5,
        runs: 4,
    };

    let change = after.against(&before);

    assert_eq!(change.score, 30);
    assert_eq!(change.swept, 60);
    assert_eq!(change.widest, 3);
    assert_eq!(change.runs, -3);
}

/// A photograph against itself moved nothing, which is the shape of an
/// operation that did not run.
#[test]
fn test_against_returns_nothing_for_a_photograph_against_itself() {
    let one = Report {
        found: true,
        score: 222,
        swept: 1 << 21,
        widest: 32,
        runs: 90,
    };

    let change = one.against(&one);

    assert_eq!(change.score, 0);
    assert_eq!(change.swept, 0);
    assert_eq!(change.widest, 0);
    assert_eq!(change.runs, 0);
}

/// Surfacing is the secret appearing where it had not been, and not merely
/// being there.
#[test]
fn test_against_reports_surfaced_only_when_the_secret_was_not_there_before() {
    let absent = quiet();
    let present = Report {
        found: true,
        ..absent
    };

    assert!(
        present.against(&absent).surfaced,
        "it appeared and was not called out"
    );
    assert!(
        !absent.against(&present).surfaced,
        "it left, which is not surfacing"
    );
    assert!(
        !present.against(&present).surfaced,
        "it was there all along"
    );
}

// ============================================================================
// Report::summary_against
// ============================================================================

#[test]
fn test_summary_against_prints_a_change_without_panicking() {
    let before = quiet();
    let after = Report {
        score: 90,
        ..quiet()
    };

    after.summary_against(&before, "something happened");
}

// ============================================================================
// Report::rows_against
// ============================================================================

/// The photograph first and what it moved second.
///
/// The two are one reading, and the other way round is a change that appears
/// to precede the thing it is a change from.
#[test]
fn test_rows_against_puts_the_photograph_before_the_change() {
    let before = quiet();
    let after = Report {
        score: 90,
        ..quiet()
    };

    let [first, second] = after.rows_against(&before, "something happened");

    assert!(first.contains("something happened"), "{first}");
    assert!(first.contains("score           90"), "{first}");
    assert!(second.contains("score           +90"), "{second}");
}

// ============================================================================
// Report::summary
// ============================================================================

#[test]
fn test_summary_prints_a_report_without_panicking() {
    quiet().summary("nothing yet");
}

// ============================================================================
// Report::row
// ============================================================================

/// The tag is padded to one width, so that rows written by different crates
/// line up under each other.
///
/// That is the whole of what the tag is for. A row whose numbers begin at a
/// different column is a readout nobody can scan down, which is how these are
/// read — a sweep over ten sizes is ten of them.
#[test]
fn test_row_puts_the_numbers_at_the_same_column_whatever_the_tag() {
    let short = quiet().row("a");
    let long = quiet().row("a tag as long as tags get");

    assert_eq!(
        short.find("score"),
        long.find("score"),
        "the numbers moved with the tag:\n{short}\n{long}",
    );
}

/// A tag wider than the column takes the room it needs rather than being cut.
///
/// Losing the end of a tag is losing which row it is, and the rows are told
/// apart by nothing else.
#[test]
fn test_row_keeps_a_tag_that_is_wider_than_the_column() {
    let tag = "a tag that is wider than the column it was given";

    assert!(quiet().row(tag).contains(tag));
}

// ============================================================================
// Change::is_noise
// ============================================================================

/// The ceiling is inclusive: a rise of exactly what chance allows is chance.
#[test]
fn test_is_noise_accepts_a_rise_of_exactly_the_ceiling() {
    let risen = Report {
        score: NOISE as u64,
        ..quiet()
    };

    assert!(risen.against(&quiet()).is_noise());
}

#[test]
fn test_is_noise_refuses_a_rise_of_one_over_the_ceiling() {
    let risen = Report {
        score: NOISE as u64 + 1,
        ..quiet()
    };

    assert!(!risen.against(&quiet()).is_noise());
}

/// A score that fell is not a rise, and nothing that is not a rise is
/// evidence.
#[test]
fn test_is_noise_accepts_a_score_that_fell() {
    let loud = Report {
        score: 4096,
        ..quiet()
    };

    assert!(quiet().against(&loud).is_noise());
}

/// The same rise reads the same however much memory the process had.
///
/// This is the property the ceiling being a constant rests on, asserted at
/// the level a caller sees it: [`crate::analysis::score::worth`] has already
/// taken the memory out, so a score means one thing everywhere. Its own tests
/// check that it does.
#[test]
fn test_is_noise_does_not_depend_on_how_much_memory_was_swept() {
    for shift in 10..40 {
        let quiet = Report {
            swept: 1 << shift,
            ..quiet()
        };
        let risen = Report {
            score: NOISE as u64 + 1,
            ..quiet
        };

        assert!(
            quiet.against(&quiet).is_noise(),
            "2^{shift} bytes and nothing moved"
        );
        assert!(
            !risen.against(&quiet).is_noise(),
            "2^{shift} bytes and a rise over the ceiling"
        );
    }
}

// ============================================================================
// Change::row
// ============================================================================

/// The change sits under the photograph it is a change from.
///
/// The two are one reading and are printed as two lines, so a change whose
/// numbers began elsewhere would read as a row of its own rather than as the
/// second half of the one above it.
#[test]
fn test_row_puts_a_change_in_the_same_column_as_the_photograph() {
    let report = quiet().row("whatever happened");
    let change = quiet().against(&quiet()).row("");

    assert_eq!(
        report.find("score"),
        change.find("score"),
        "the two halves of one reading begin at different columns:\n{report}\n{change}",
    );
}

// ============================================================================
// Display for Report
// ============================================================================

/// Every number a reader is asked to compare is in the line, and the exact
/// one is named rather than printed as a bit.
#[test]
fn test_report_displays_every_number_it_holds() {
    let report = Report {
        found: true,
        score: 222,
        swept: 4096,
        widest: 32,
        runs: 7,
    };

    let shown = report.to_string();

    for number in ["222", "32", "7", "4096"] {
        assert!(shown.contains(number), "{number} is missing from {shown}");
    }

    assert!(
        shown.contains("yes"),
        "the whole secret was there and the line does not say so"
    );
}

// ============================================================================
// Display for Change
// ============================================================================

/// A rise and a fall read differently at a glance, which is the only reason
/// this is not `Debug`.
#[test]
fn test_change_displays_a_rise_with_its_sign() {
    let risen = Report {
        score: 222,
        ..quiet()
    };

    assert!(risen.against(&quiet()).to_string().contains("+222"));
    assert!(quiet().against(&risen).to_string().contains("-222"));
}

/// Surfacing is the one thing a number cannot say, so it is said in words.
#[test]
fn test_change_says_when_the_whole_secret_surfaced() {
    let absent = quiet();
    let present = Report {
        found: true,
        ..absent
    };

    assert!(present.against(&absent).to_string().contains("surfaced"));
    assert!(!absent.against(&absent).to_string().contains("surfaced"));
}
