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

/// Said out loud when the machine has no register to hide a secret in.
///
/// The pair below asks whether the capture reaches a place the sweep cannot,
/// and on a machine with no such place there is nothing to ask. What there
/// must not be is a green that read nothing looking like a green that read
/// everything.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! wide {
    () => {
        if !has_a_register_nothing_writes() {
            eprintln!(
                "skipped: this machine has no register the compiler is obliged \
                 to leave alone, so the capture has nothing here to reach."
            );

            return Ok(());
        }
    };
}

/// Sixteen bytes nothing else in this process is holding.
///
/// Sixteen and not thirty-two, because on one of the two architectures below
/// the part of the register the compiler leaves alone begins at a hundred and
/// twenty-eight bits, and a needle that straddles that line is half in a place
/// anything may overwrite.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const HELD: [u8; 16] = [
    0x9E, 0x41, 0xD7, 0x2B, 0x60, 0xFA, 0x35, 0xC8, 0x1D, 0xB4, 0x7F, 0x02, 0xE6, 0x59, 0xA3, 0x18,
];

/// A needle built backwards, so that asking the question does not put the
/// answer in the process.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn backwards(of: &[u8]) -> Vec<u8> {
    let mut needle = Vec::with_capacity(of.len());

    for at in (0..of.len()).rev() {
        needle.push(of[at]);
    }

    needle
}

/// Whether this machine has a register the compiler is obliged to leave alone.
///
/// Not a property of the code. `zmm16-31` exist where there is `avx512`, and
/// above the first hundred and twenty-eight bits of `z0-z31` exists where
/// there is SVE wide enough to have an above — a machine whose vector length
/// is sixteen bytes has nothing past what NEON already uses.
#[cfg(target_arch = "x86_64")]
fn has_a_register_nothing_writes() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
}

/// The same question where the answer is a length.
#[cfg(target_arch = "aarch64")]
fn has_a_register_nothing_writes() -> bool {
    std::arch::is_aarch64_feature_detected!("sve") && vector_length() > 16
}

/// How many bytes wide this machine's SVE registers are.
#[cfg(target_arch = "aarch64")]
fn vector_length() -> usize {
    let bytes: u64;

    // SAFETY: reads the vector length into a register of the compiler's
    // choosing and touches nothing else. Guarded by the feature check above,
    // which is why this is never reached on a machine without SVE.
    unsafe {
        core::arch::asm!(
            ".arch_extension sve",
            "rdvl {bytes}, #1",
            ".arch_extension nosve",
            bytes = out(reg) bytes,
            options(nomem, nostack),
        );
    }

    bytes as usize
}

/// The secret put where only the capture can reach it, and then read.
///
/// The seeding is in the measured block and the capture is the macro's, so
/// between the two the compiler may put anything in a register it is entitled
/// to use. These are the ones it is not: `zmm16-31` are reachable only by
/// `avx512` encodings, which nothing here compiles. A value left there is
/// still there when the macro looks — which is the case the capture exists
/// for, since a wide `memcpy` of a key leaves it in exactly these and nothing
/// in the process ever clears them.
///
/// The buffer is as wide as the load, because the load is what decides: this
/// one reads sixty-four bytes whatever the secret's length.
///
/// It is erased before the block ends, so at the moment of the photograph the
/// register is the only place the secret is.
#[cfg(target_arch = "x86_64")]
fn only_in_a_wide_register() {
    let mut from = [0_u8; 64];

    from[..HELD.len()].copy_from_slice(&HELD);

    // SAFETY: one write to one vector register, declared, reading the sixty-
    // four bytes the buffer has and no more. The load is unaligned.
    unsafe {
        core::arch::asm!(
            "vmovdqu64 zmm16, [{from}]",
            from = in(reg) from.as_ptr(),
            out("zmm16") _,
        );
    }

    erase(&mut from);
}

/// The same, where the register the compiler leaves alone is the far end of
/// one it uses.
///
/// `z16` past its first hundred and twenty-eight bits. The low half is `v16`,
/// which ordinary compiled code writes whenever it feels like it; everything
/// above is reachable by SVE encodings alone, and nothing here compiles any.
/// So the secret goes at sixteen bytes in, and what sits below it is padding
/// whose fate nobody cares about.
///
/// `ldr` and not a predicated load: it moves the whole register, so the buffer
/// is the vector length and there is no predicate register to name — and which
/// predicates Rust will hand out is a question with a different answer on
/// every toolchain.
#[cfg(target_arch = "aarch64")]
fn only_in_a_wide_register() {
    let wide = vector_length();
    let mut from = vec![0_u8; wide];

    from[16..16 + HELD.len()].copy_from_slice(&HELD);

    // SAFETY: one write to one vector register, declared as the NEON half that
    // Rust can name, reading exactly the vector length the buffer was made
    // from.
    unsafe {
        core::arch::asm!(
            ".arch_extension sve",
            "ldr z16, [{from}]",
            ".arch_extension nosve",
            from = in(reg) from.as_ptr(),
            out("v16") _,
        );
    }

    erase(&mut from);
}

/// The buffer, gone before the block ends.
///
/// Volatile, because nothing reads these bytes afterwards and that is exactly
/// the write an optimiser may delete. If it did, the buffer would be a second
/// place the secret is, and the pair below would agree for a reason that has
/// nothing to do with the capture.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn erase(from: &mut [u8]) {
    for byte in from.iter_mut() {
        // SAFETY: a `&mut u8` is valid to write through, volatile or not.
        unsafe { core::ptr::write_volatile(byte, 0) };
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_the_macro_captures_a_register_the_sweep_cannot_otherwise_reach() -> Result<(), Reason> {
    alone!();
    wide!();

    let mut watch = crate::Forensics::watching(&backwards(&HELD))?;

    let with = crate::forensics!(watch, {
        only_in_a_wide_register();
    });

    assert!(
        with.found,
        "the secret was in a register nothing else writes and the photograph \
         did not have it, so the capture did not happen: {with}",
    );

    Ok(())
}

/// And the same block without the capture, which must find nothing.
#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_without_the_capture_a_register_is_out_of_reach() -> Result<(), Reason> {
    alone!();
    wide!();

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
