// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What opening the master key leaves behind.
//!
//! The needle is the key itself, opened once and turned around where it lies.
//! What is held from then on is the key backwards, which is not the key — and
//! that first open is the one contamination in here.
//!
//! # Why a difference is not enough
//!
//! Subtracting two photographs does not make that contamination go away. A
//! residue that vanishes while another appears reads as no change at all, and
//! so does a leak that lands exactly where the last one was overwritten. The
//! difference says what an operation *moved*, which is not the same as what
//! is there.
//!
//! So every photograph is also held to an absolute bound — [`QUIET`], the
//! widest run memory throws up by accident — and the first one is held to it
//! before anything has been opened at all. That one owes nothing to any other
//! photograph, and it is what makes the differences below worth reading.
//!
//! # What it caught
//!
//! `copy_from_slice` is `core::ptr::copy_nonoverlapping` underneath, and over
//! a runtime length that is a call into the C library's `memcpy`. glibc's
//! leaves the whole key in `zmm16` and `zmm17` — registers no form of
//! `vzeroall` reaches and compiled code never writes. On this instrument a
//! single open scored 222 with a run of all thirty-two bytes and the whole key
//! surfacing. The copy that replaced it scores nothing.
//!
//! So the assertions below are the shape of a regression that already
//! happened once.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_vault_core::leak_master_key;

/// How much of the key is taken, which is all of it.
const WIDE: usize = 32;

/// One round leaving nothing is a weaker claim than it looks.
///
/// A piece surviving one open in fifty would not show once and would show
/// plainly at two hundred.
const ROUNDS: usize = 200;

/// The key, opened and turned around where it lies.
///
/// Turned around in place and never copied forwards: a `to_vec` followed by a
/// `reverse` would put the key the right way round on the heap for as long as
/// it takes to turn it over, and that is the very thing being measured.
fn backwards() -> Vec<u8> {
    let mut needle = leak_master_key(WIDE).expect("no master key");

    needle.reverse();

    needle.to_vec()
}

/// The sweep finds the key when the key is plainly there.
///
/// Every zero the test below reports is worth exactly what this one is worth.
/// A sweep that reached no memory at all answers `no` to everything, and so
/// does a process that is genuinely clean — the two are the same answer, and
/// only a copy the sweep has to find tells them apart.
///
/// What is held is the key as `leak_master_key` produces it, and not a value
/// rebuilt from the needle: the question is whether the sweep reaches where
/// that function actually puts it.
///
/// It is a test of its own, and that is the point. `nextest` gives each test a
/// process, so a key held in plain sight here is in nobody else's memory. As
/// one more step inside the other test it would have had to come last, after
/// everything it was meant to vouch for had already been measured.
#[test]
fn test_the_sweep_finds_the_master_key_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    // A real open, and nothing done to hide it.
    let held = leak_master_key(WIDE).expect("no master key");

    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the key, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where the master key lives, so every absence \
         this file reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box(held));

    Ok(())
}

/// A piece of the key kept on purpose is not read as chance.
///
/// # What it calibrates
///
/// Two things, and neither is a restatement of the other.
///
/// A count says `no`. Eight bytes are not the key, so nothing that searches
/// for the key finds them — truthfully, and uselessly. That is the whole
/// reason the score exists, and this is where it is demonstrated rather than
/// argued.
///
/// And the two thresholds agree. [`QUIET`] is this crate's own statement that
/// a run of eight bytes is the widest memory throws up by accident. A run of
/// exactly that width, put there deliberately, must therefore not read as
/// accident to the score either. Raise one of the two without the other and
/// this test is what notices.
///
/// A process of its own, because it plants key material on purpose.
#[test]
fn test_a_piece_of_the_master_key_kept_is_not_read_as_chance() -> Result<(), AnyError> {
    /// As wide as the widest run [`QUIET`] allows, and a quarter of the key.
    const PIECE: usize = QUIET as usize;

    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    // From the middle, not the front: a prefix is what a search for the key
    // would stumble onto anyway. The key itself goes at the end of the block,
    // so what is left alive is the piece and nothing else.
    let kept = {
        let key = leak_master_key(WIDE).expect("no master key");

        key[8..8 + PIECE].to_vec()
    };

    core::hint::black_box(&kept);

    let report_after = watch.snapshot()?;
    let delta = report_after.against(&report_before);

    println!();
    report_before.summary("nothing kept yet");
    report_after.summary_against(&report_before, &format!("{PIECE} bytes kept"));
    println!();

    assert!(
        !report_after.found,
        "a search for the whole key found {PIECE} bytes of it, which it cannot: \
         {report_after}",
    );

    assert!(
        report_after.widest >= PIECE as u64,
        "{PIECE} bytes of the key are in plain sight and the widest run is {}: \
         {report_after}",
        report_after.widest,
    );

    assert!(
        !delta.is_noise(),
        "{PIECE} bytes of the key read as chance, which is what {QUIET} says they are not: \
         {delta}",
    );

    drop(core::hint::black_box(kept));

    Ok(())
}

/// Opening it leaves nothing, once or two hundred times.
///
/// The control comes last and not first: planted at the top it would be in
/// every photograph after it, and there would be nothing left to measure.
#[test]
fn test_opening_the_master_key_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    let report_after_opening = forensics!(watch, {
        let key = leak_master_key(WIDE).expect("no master key");

        core::hint::black_box(key[0]);
    });

    let report_after_opening_often = forensics!(watch, {
        for _ in 0..ROUNDS {
            let key = leak_master_key(WIDE).expect("no master key");

            core::hint::black_box(key[0]);
        }
    });

    let planted = core::hint::black_box(needle.iter().rev().copied().collect::<Vec<u8>>());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing opened yet");
    report_after_opening.summary_against(&report_before, "opened once");
    report_after_opening_often
        .summary_against(&report_after_opening, &format!("opened {ROUNDS} times"));
    println!();
    report_in_plain_sight.summary_against(&report_after_opening_often, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reached nowhere, so no zero above means anything: \
         {report_in_plain_sight}",
    );

    // The absolute bound, on every photograph — the first one included, before
    // anything had been opened. Nothing here is a difference, so nothing here
    // can be cancelled by one residue replacing another.
    for (what, report) in [
        ("the open that made the needle", &report_before),
        ("one open", &report_after_opening),
        (&format!("{ROUNDS} opens"), &report_after_opening_often),
    ] {
        assert!(
            !report.found,
            "the whole key was left behind by {what}: {report}"
        );

        assert!(
            report.widest <= QUIET,
            "a run of {} bytes of the key was left behind by {what}, and {QUIET} is \
             what memory has by accident: {report}",
            report.widest,
        );
    }

    // And the differences, which say what each operation moved. Finer than the
    // bound above, and worth nothing without it.
    let delta_once = report_after_opening.against(&report_before);

    assert!(
        delta_once.is_noise(),
        "one open moved the score past chance: {delta_once}"
    );

    let delta_often = report_after_opening_often.against(&report_before);

    assert!(
        delta_often.is_noise(),
        "{ROUNDS} opens moved the score past chance: {delta_often}"
    );

    drop(core::hint::black_box(planted));

    Ok(())
}
