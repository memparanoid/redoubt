// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a run is worth, read through the numbers a caller gets.
//!
//! # Not the same question as reach
//!
//! Whether the sweep arrives where a value lives is settled next door, and the
//! absences there rest on presences of their own. What is asked here is what
//! the weighing makes of what arrived: a wide piece against a narrow one, a
//! quiet process against a loud one, one photograph against another.
//!
//! The two are apart because the controls are different. A reach test is
//! controlled by a copy in the place the operation writes; a score test is
//! controlled by the quiet process beside the loud one.
//!
//! # A process each
//!
//! The memory being read is the whole process's. Two tests in one process are
//! two secrets in one process, and each is the other's needle.
//!
//! `cargo nextest run`, which gives each test a process. Under `cargo test`
//! every test here skips itself and says so.

#![cfg(target_os = "linux")]

use redoubt_forensics::{Forensics, Reason, Report, forensics, freeze};

mod support;

use support::helpers::alone;

// ============================================================================
// The material
// ============================================================================

/// Thirty-two distinct bytes, so that a stretch of it is a stretch of it and
/// not a walk that happened to agree.
const ALPHA: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// [`ALPHA`] with one byte doubled, so that its table has one pair a byte can
/// walk without end. A page of that byte walks it a page wide, and the secret
/// has two of it.
///
/// A `static` and not a `const`: a const is materialized wherever it is used,
/// which puts a copy of it on the stack this file is measuring, and the absence
/// below then reads as the whole secret surfacing.
static DOUBLED: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x71, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A value this file never copies into memory anything can write to.
const ABSENT: [u8; 32] = [
    0x4B, 0xE9, 0x26, 0x7C, 0x01, 0x9D, 0x58, 0xB3, 0x3E, 0xCF, 0x14, 0x82, 0x6A, 0x2B, 0xD0, 0x75,
    0xA9, 0x08, 0xF3, 0x5C, 0x37, 0xE0, 0x91, 0x4D, 0xBA, 0x1F, 0x68, 0xC4, 0x83, 0x20, 0xD7, 0x46,
];

/// What a sixteen byte piece is worth, near enough.
///
/// Fifteen steps of eight bits each, less the twenty-odd that a few megabytes
/// of memory throws up by chance, is a little under a hundred. The floor here
/// is generous: it stays true for a process a thousand times larger, where the
/// same piece is worth ninety.
const LEAK: u64 = 80;

/// The widest run a process that is holding nothing may have.
///
/// Runs of one and two are what any memory has by accident. Three is already
/// unlikely and four is not expected once in a thousand runs of this file.
const QUIET: u64 = 4;

// ============================================================================
// The tools
// ============================================================================

/// A needle, built from its last byte to its first.
///
/// Backwards from the start and never turned around. A `to_vec` followed by a
/// `reverse` would put the value forwards on the heap for as long as it takes
/// to turn it over, and a vectorised reverse can spill half of it to the stack
/// on the way — which is the very thing being measured.
fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// An instrument watching for that value, reserved before anything happens.
fn watching(of: &[u8]) -> Result<Forensics, Reason> {
    Forensics::watching(&backwards(of))
}

/// One photograph.
fn photograph(watch: &mut Forensics) -> Result<Report, Reason> {
    watch.snapshot()
}

// ============================================================================
// Report
// ============================================================================

/// A process holding none of it scores nothing at all — not "little", nothing.
/// The floor is arithmetic and not a threshold somebody chose.
#[test]
fn test_a_quiet_process_scores_nothing() -> Result<(), Reason> {
    alone!();

    let report = photograph(&mut watching(&ABSENT)?)?;

    assert_eq!(report.score, 0, "{report}");
    assert!(report.widest <= QUIET, "{report}");

    Ok(())
}

/// A piece kept is a run as wide as the piece.
#[test]
fn test_a_piece_kept_is_as_wide_as_the_piece() -> Result<(), Reason> {
    alone!();

    let kept = core::hint::black_box(ALPHA[8..24].to_vec());
    let report = photograph(&mut watching(&ALPHA)?)?;

    assert!(report.widest >= 16, "{report}");
    assert!(report.score >= LEAK, "{report}");
    assert!(!report.found, "a piece is not the whole of it: {report}");

    drop(core::hint::black_box(kept));

    Ok(())
}

/// A wider piece is worth more than a narrower one, which is the whole point of
/// weighing rather than counting.
#[test]
fn test_a_wider_piece_is_worth_more_than_a_narrower_one() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    let narrow = core::hint::black_box(ALPHA[..8].to_vec());
    let less = photograph(&mut watch)?;

    let wide = core::hint::black_box(ALPHA[8..].to_vec());
    let more = photograph(&mut watch)?;

    assert!(more.score > less.score, "{less} then {more}");
    assert!(more.widest > less.widest, "{less} then {more}");

    drop(core::hint::black_box((narrow, wide)));

    Ok(())
}

/// A piece of [`DOUBLED`] that is really there is found and weighed, which is
/// what the absence below is worth.
///
/// Its own presence rather than [`ALPHA`]'s: the two differ in the byte at
/// fifteen, and that byte is the whole of what the absence is about. A sweep
/// that answered nothing for this needle whatever the process held would leave
/// that absence saying only that the sweep is broken.
#[test]
fn test_a_piece_of_a_secret_that_doubles_a_byte_is_still_weighed() -> Result<(), Reason> {
    alone!();

    let kept = core::hint::black_box(DOUBLED[8..24].to_vec());
    let report = photograph(&mut watching(&DOUBLED)?)?;

    assert!(report.widest >= 16, "{report}");
    assert!(report.score >= LEAK, "{report}");

    drop(core::hint::black_box(kept));

    Ok(())
}

/// A page of one byte is not a run a page wide, however far the secret's pairs
/// let it walk: the secret has two of that byte in a row, and two is what the
/// page is worth.
///
/// This is what a vector register broadcast leaves on the stack — sixteen
/// copies of one byte — and it was read as a run of sixteen whenever the byte
/// happened to be one the secret doubles.
#[test]
fn test_a_page_of_a_byte_the_secret_doubles_is_a_run_of_two() -> Result<(), Reason> {
    alone!();

    let page = core::hint::black_box(vec![DOUBLED[15]; 4096]);
    let report = photograph(&mut watching(&DOUBLED)?)?;

    assert!(report.widest <= QUIET, "{report}");
    assert!(!report.found, "{report}");

    drop(core::hint::black_box(page));

    Ok(())
}

// ============================================================================
// Report::against
// ============================================================================

/// An operation that keeps a piece shows up in the difference between the
/// photograph before it and the one after.
#[test]
fn test_the_difference_shows_what_an_operation_kept() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;
    let before = photograph(&mut watch)?;

    forensics!({
        let mut kept = vec![0_u8; 16];

        // Through the copy whose registers are probed: one the compiler emits
        // leaves the piece in a vector register too, and the capture then puts
        // it in the difference whether or not the copy on the heap is read.
        // SAFETY: sixteen bytes from inside `ALPHA` into a vector of sixteen,
        // two allocations apart.
        unsafe {
            redoubt_mem_core::copy_nonoverlapping(ALPHA[8..].as_ptr(), kept.as_mut_ptr(), 16)
        };

        core::hint::black_box(&kept);

        freeze!();

        core::mem::forget(kept);
    });

    let after = photograph(&mut watch)?;
    let change = after.against(&before);

    // The score and not the width: a quiet process scores exactly nothing, so
    // subtracting one takes nothing off the margin. Its widest is `QUIET`, and
    // a floor on that difference is a floor short by however quiet the process
    // happened to be — which is why the width is asserted where it needs no
    // subtraction, against the photograph itself.
    assert!(
        change.score >= i128::from(LEAK),
        "{before}\n{after}\n{change}"
    );

    Ok(())
}

/// An operation that keeps nothing shows up as nothing.
///
/// Two lines apart from the one above rather than one, and it cannot be closer:
/// a `free` hands the chunk back without emptying it, so the same needle with
/// the copy dropped is a needle still lying in a mapping the sweep reads. The
/// only operation that keeps nothing is one that never wrote it.
#[test]
fn test_the_difference_shows_nothing_for_an_operation_that_kept_nothing() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ABSENT)?;
    let before = photograph(&mut watch)?;

    forensics!({
        core::hint::black_box(1_u8);

        freeze!();
    });

    let after = photograph(&mut watch)?;
    let change = after.against(&before);

    assert_eq!(change.score, 0, "{before}\n{after}\n{change}");

    Ok(())
}

// ============================================================================
// The readout
// ============================================================================

/// Every number this crate answers with, for a process holding nothing and the
/// same process holding sixteen bytes. Asserts nothing; run it with
/// `cargo nextest run --no-capture`.
#[test]
fn test_reads_out_a_leak_beside_no_leak() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    let quiet_before = photograph(&mut watch)?;
    let quiet_after = photograph(&mut watch)?;

    let loud_before = photograph(&mut watch)?;
    let kept = core::hint::black_box(ALPHA[8..24].to_vec());
    let loud_after = photograph(&mut watch)?;

    eprintln!();
    eprintln!("  nothing kept");
    eprintln!("    before  {quiet_before}");
    eprintln!("    after   {quiet_after}");
    eprintln!("    change  {}", quiet_after.against(&quiet_before));
    eprintln!();
    eprintln!("  sixteen bytes kept");
    eprintln!("    before  {loud_before}");
    eprintln!("    after   {loud_after}");
    eprintln!("    change  {}", loud_after.against(&loud_before));
    eprintln!();

    drop(core::hint::black_box(kept));

    Ok(())
}
