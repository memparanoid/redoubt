// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the macro does with what the measured block answered.
//!
//! # Why this is asserted here and not where the macro is used
//!
//! Half of [`Outcome`] is for blocks that can fail, and nothing in this crate
//! has a block that can — every measurement here is of work that cannot go
//! wrong. So the half a caller reaches for most is the half this crate never
//! touches, and it was covered by nobody: the crates that use it are the ones
//! exercising it, and their coverage is theirs.
//!
//! [`settle`](Outcome::settle) is what the whole of it comes down to, and it
//! takes two arguments that can each be either way round. All four are below.
//!
//! # The order it puts them in
//!
//! The operation is asked first and the photograph second, because that is the
//! order they happened in. A block that failed is still photographed — the
//! photograph is taken before either is read — and then thrown away, because
//! a measurement of an operation that did not finish measures nothing.

use crate::analysis::report::Report;
use crate::errors::Reason;
use crate::macros::Outcome;

/// A photograph, as the settled value carries one.
///
/// Nothing reads it; what is asserted is which of the two arguments came back,
/// so it only has to be one this file can recognise.
fn taken() -> Report {
    Report {
        found: true,
        score: 1,
        widest: 2,
        runs: 3,
        swept: 4,
    }
}

// ============================================================================
// impl Outcome for ()
// ============================================================================

/// A block with nothing to answer for hands back the photograph.
#[test]
fn test_a_block_that_cannot_fail_settles_as_the_photograph() {
    let settled = Outcome::settle((), Ok(taken()));

    assert_eq!(settled, Ok(taken()));
}

/// And when the photograph is the thing that failed, that is the answer.
///
/// There is nothing else it could be: the block had no error to give, so the
/// only reason there can be is the photograph's own.
#[test]
fn test_a_block_that_cannot_fail_settles_as_the_photograph_that_would_not_be_taken() {
    let settled = Outcome::settle((), Err(Reason::NoPhotograph));

    assert_eq!(settled, Err(Reason::NoPhotograph));
}

// ============================================================================
// impl Outcome for Result<T, E>
// ============================================================================

/// A block that could have failed and did not.
#[test]
fn test_a_block_that_went_well_settles_as_the_photograph() {
    let settled = Outcome::settle(Ok::<(), Reason>(()), Ok(taken()));

    assert_eq!(settled, Ok(taken()));
}

/// A block that failed is the answer, and the photograph is thrown away.
///
/// Both arguments are here something a caller would want, and the operation's
/// failure wins — measuring what an operation left when the operation did not
/// finish is measuring nothing, and answering with that reading would say it
/// left nothing.
#[test]
fn test_a_block_that_failed_settles_as_its_own_failure_and_not_the_photograph() {
    let settled = Outcome::settle(Err::<(), Reason>(Reason::TooManyBlocks), Ok(taken()));

    assert_eq!(settled, Err(Reason::TooManyBlocks));
}

/// And when both went wrong, the block's is what comes back.
///
/// The one that says why the measurement is worthless, rather than the one
/// that says the worthless measurement could not be taken.
#[test]
fn test_a_block_that_failed_wins_over_a_photograph_that_failed_too() {
    let settled = Outcome::settle(
        Err::<(), Reason>(Reason::TooManyBlocks),
        Err(Reason::NoPhotograph),
    );

    assert_eq!(settled, Err(Reason::TooManyBlocks));
}

/// A photograph that failed becomes the block's own kind of error.
///
/// Which is what `E: From<Reason>` is for, and the reason a caller writes one
/// error type and gets both. Asserted with an error that is not a `Reason`,
/// because a `Reason` converting into itself would pass without the
/// conversion existing.
#[test]
fn test_a_photograph_that_failed_arrives_as_the_blocks_own_error() {
    /// A caller's error, of which a refusal by the instrument is one case.
    #[derive(Debug, Eq, PartialEq)]
    enum Mine {
        Instrument(Reason),
    }

    impl From<Reason> for Mine {
        fn from(why: Reason) -> Self {
            Self::Instrument(why)
        }
    }

    let settled = Outcome::settle(Ok::<(), Mine>(()), Err(Reason::NoMappings));

    assert_eq!(settled, Err(Mine::Instrument(Reason::NoMappings)));
}
