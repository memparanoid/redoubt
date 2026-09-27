// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The word a reason travels as, and what comes back when it is read again.
//!
//! # Why the round trip is the whole of it
//!
//! [`Reason::code`] and [`Reason::from_code`] are two tables written by hand,
//! one going each way, and nothing in the language holds them to each other. A
//! number changed on one side and not the other turns one reason into another
//! somewhere between two processes — and the caller is told, plausibly and
//! wrongly, what went wrong.
//!
//! So what is asserted is not that `NoFork` is four. It is that every reason
//! comes back as itself, which stays true when somebody renumbers them all.

use crate::errors::{AnyError, DONE, Reason};

/// Every reason there is.
///
/// Written out rather than derived: the enum is `non_exhaustive` and there is
/// no way to ask it for its variants, so a new one has to be added here by
/// hand. A test that silently stopped covering a variant would be worse than
/// one that has to be edited, and this is the file where that is noticed.
const EVERY: [Reason; 9] = [
    Reason::Needle,
    Reason::NoFloor,
    Reason::NoPipe,
    Reason::NoFork,
    Reason::NoAnswer,
    Reason::NoPhotograph,
    Reason::NoMappings,
    Reason::TooManyMappings,
    Reason::TooManyBlocks,
];

// ============================================================================
// Reason::code
// ============================================================================

/// No two reasons travel as the same word.
///
/// Two sharing a number is one of them arriving as the other, and the reader
/// has no way to tell — both are perfectly ordinary answers.
#[test]
fn test_code_gives_a_different_word_to_every_reason() {
    for (at, one) in EVERY.iter().enumerate() {
        for other in &EVERY[at + 1..] {
            assert_ne!(
                one.code(),
                other.code(),
                "{one:?} and {other:?} travel as the same word",
            );
        }
    }
}

/// No reason travels as the word success does.
///
/// A reason numbered [`DONE`] is a failure the parent reads as a clean
/// photograph, which is the one mistake this crate exists to avoid.
#[test]
fn test_code_gives_no_reason_the_word_success_has() {
    for one in &EVERY {
        assert_ne!(one.code(), DONE, "{one:?} travels as success");
    }
}

// ============================================================================
// Reason::from_code
// ============================================================================

/// Every reason, sent and read again, is the reason it was.
///
/// The one assertion this file is for. It holds whatever the numbers are, so
/// renumbering them all at once cannot break it and changing one of the two
/// tables alone cannot pass it.
#[test]
fn test_from_code_returns_the_reason_the_word_came_from() {
    for one in &EVERY {
        assert_eq!(
            Reason::from_code(one.code()),
            *one,
            "{one:?} came back as something else",
        );
    }
}

/// A word that is no reason at all is an analyst that did not finish saying
/// what it meant.
///
/// Zero is the block as it was reserved, so an analyst that wrote nothing
/// reads as zero — and that must not be some reason it happens to number.
#[test]
fn test_from_code_returns_no_answer_for_a_word_that_is_not_a_reason() {
    assert_eq!(Reason::from_code(0), Reason::NoAnswer);
    assert_eq!(Reason::from_code(u64::MAX), Reason::NoAnswer);
}

/// Including the word success has, which is not this function's to answer.
///
/// Reading it here would be an analyst that succeeded read as one that never
/// spoke. Nothing asks: the caller matches [`DONE`] before it asks for a
/// reason at all, and this says what the answer would be if one ever did.
#[test]
fn test_from_code_returns_no_answer_for_the_word_success_has() {
    assert_eq!(Reason::from_code(DONE), Reason::NoAnswer);
}

// ============================================================================
// Reason: Display
// ============================================================================

/// No two reasons read the same.
///
/// The one mistake a hand-written table of sentences makes is two arms
/// carrying the same one, and a reader looking at the message has then been
/// told the wrong thing with no way to know.
#[test]
fn test_display_says_something_different_for_every_reason() {
    for (at, one) in EVERY.iter().enumerate() {
        assert!(!one.to_string().is_empty(), "{one:?} says nothing");

        for other in &EVERY[at + 1..] {
            assert_ne!(
                one.to_string(),
                other.to_string(),
                "{one:?} and {other:?} read the same",
            );
        }
    }
}

// ============================================================================
// AnyError
// ============================================================================

/// What a test sees when it prints one is the error, not the wrapper.
///
/// A failing test names what it hit. A wrapper that printed itself would give
/// the reader the name of a box.
#[test]
fn test_debug_is_the_error_and_not_the_wrapper() {
    let wrapped = AnyError::from(Reason::NoPhotograph);

    assert_eq!(
        format!("{wrapped:?}"),
        format!("{:?}", Reason::NoPhotograph)
    );
}

/// It takes anything that is an error, not only this crate's.
///
/// Which is the whole reason it exists: a test measuring fallible work has a
/// second source of error, and one type has to reach both.
#[test]
fn test_it_takes_an_error_from_anywhere() {
    let elsewhere = std::io::Error::other("a refusal from somewhere else");
    let wrapped = AnyError::from(elsewhere);

    assert!(format!("{wrapped:?}").contains("a refusal from somewhere else"));
}

/// `?` reaches it without anybody naming a type.
///
/// The shape every test in this workspace is written in. If the conversion
/// ever needed an annotation, every one of them would stop compiling — which
/// is a loud failure, but this says so in one place and in one line.
#[test]
fn test_the_question_mark_reaches_it_from_either_side() -> Result<(), AnyError> {
    fn refused() -> Result<(), Reason> {
        Err(Reason::Needle)
    }

    assert!(matches!(refused(), Err(Reason::Needle)));

    let asked: Result<(), std::io::Error> = Ok(());

    asked?;

    Ok(())
}
