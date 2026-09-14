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

// ============================================================================
// forensics!
// ============================================================================

/// Its own process, for the reason every photograph here needs one: a sweep
/// reads the whole of it, so two of these at once are two secrets in one
/// process and each is the other's needle.
macro_rules! alone {
    () => {
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!("skipped: this test needs a process of its own. `cargo nextest run`.");

            return Ok(());
        }
    };
}

/// Thirty-two bytes nothing else in this process is holding.
#[cfg(target_arch = "x86_64")]
const HELD: [u8; 32] = [
    0x9E, 0x41, 0xD7, 0x2B, 0x60, 0xFA, 0x35, 0xC8, 0x1D, 0xB4, 0x7F, 0x02, 0xE6, 0x59, 0xA3, 0x18,
    0xCB, 0x74, 0x2D, 0x90, 0x46, 0xEF, 0x83, 0x1A, 0x57, 0xBC, 0x09, 0xD3, 0x6E, 0xF1, 0x24, 0xA8,
];

/// A needle built backwards, so that asking the question does not put the
/// answer in the process.
#[cfg(target_arch = "x86_64")]
fn backwards(of: &[u8]) -> Vec<u8> {
    let mut needle = Vec::with_capacity(of.len());

    for at in (0..of.len()).rev() {
        needle.push(of[at]);
    }

    needle
}

/// The secret put where only the capture can reach it, and then read.
///
/// `zmm16` and nothing else: the seeding is in the measured block and the
/// capture is the macro's, so between the two the compiler may put anything in
/// a register it is entitled to use. `zmm16-31` are the ones it never writes —
/// they exist for `avx512` code, which nothing here compiles — so a value left
/// there is still there when the macro looks. Which is the case the capture
/// exists for: a wide `memcpy` of a key leaves it in these, and nothing in the
/// process ever clears them.
///
/// The buffer it was loaded from is erased before the block ends, so at the
/// moment of the photograph the register is the only place it is.
#[cfg(target_arch = "x86_64")]
fn only_in_a_wide_register() {
    let mut from = HELD;

    // SAFETY: one write to one vector register, declared, reading the
    // thirty-two bytes the buffer has. The load is unaligned.
    unsafe {
        core::arch::asm!(
            "vmovdqu64 zmm16, [{from}]",
            from = in(reg) from.as_ptr(),
            out("zmm16") _,
        );
    }

    // Volatile, because nothing reads these bytes afterwards and that is
    // exactly the write an optimiser may delete. If it did, the buffer would
    // be the second place the secret is and the pair below would agree for a
    // reason that has nothing to do with the capture.
    for at in 0..from.len() {
        unsafe { core::ptr::write_volatile(from.as_mut_ptr().add(at), 0) };
    }
}

/// What the capture is worth, as the difference between two runs of the same
/// block.
///
/// Every other test of this crate leaves its secret in memory, so each of them
/// answers the same whether or not the macro takes the capture at all: delete
/// that line and the suite stays green. This pair is what goes red.
///
/// The two halves run the same work and differ in one line of macro. The first
/// says the capture reaches a register; the second says the register is
/// genuinely out of the sweep's reach without it — and if the second ever finds
/// the secret, the first was proving nothing.
#[test]
#[cfg(target_arch = "x86_64")]
fn test_the_macro_captures_a_register_the_sweep_cannot_otherwise_reach() -> Result<(), Reason> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx512f") {
        eprintln!(
            "skipped: no avx512 here, so there is no register the compiler is \
             guaranteed to leave alone."
        );

        return Ok(());
    }

    let mut watch = crate::Forensics::watching(&backwards(&HELD))?;

    let with = crate::forensics!(watch, {
        only_in_a_wide_register();
    });

    assert!(
        with.found,
        "the secret was in zmm16 and the photograph did not have it, so the \
         capture did not happen: {with}",
    );

    Ok(())
}

/// And the same block without the capture, which must find nothing.
#[test]
#[cfg(target_arch = "x86_64")]
fn test_without_the_capture_a_register_is_out_of_reach() -> Result<(), Reason> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx512f") {
        eprintln!(
            "skipped: no avx512 here, so there is no register the compiler is \
             guaranteed to leave alone."
        );

        return Ok(());
    }

    let mut watch = crate::Forensics::watching(&backwards(&HELD))?;

    let without = crate::macros::without_the_capture!(watch, {
        only_in_a_wide_register();
    });

    assert!(
        !without.found,
        "the secret was reachable with no capture taken, so the test beside \
         this one proves nothing about the capture: {without}",
    );

    Ok(())
}
