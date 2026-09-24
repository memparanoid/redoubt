// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
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

/// The three things an absence has to survive.
///
/// The whole key is gone, no piece of it wider than chance is left, and the
/// score did not move. The first two are absolute and owe nothing to any other
/// photograph, which is what makes the third worth reading.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing opened yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole key was left behind by {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes of the key was left behind by {what}, and {QUIET} is \
         what memory has by accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(
        delta.is_noise(),
        "{what} moved the score past chance: {delta}"
    );
}

// ============================================================================
// leak_master_key
// ============================================================================

/// The sweep finds the key when the key is plainly there.
///
/// Every zero the tests below report is worth exactly what this one is worth.
/// A sweep that reached no memory at all answers `no` to everything, and so
/// does a process that is genuinely clean — the two are the same answer, and
/// only a copy the sweep has to find tells them apart.
///
/// What is held is the key as `leak_master_key` produces it, and not a value
/// rebuilt from the needle: the question is whether the sweep reaches where
/// that function actually puts it.
#[test]
fn test_the_master_key_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        // A real open, and nothing done to hide it.
        let held = capture(|| leak_master_key(WIDE))?;

        // Kept rather than let go, which is the one line between this and the
        // test below. Emits no code, so the two are the same measurement of
        // the same call.
        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("the key, held");
    println!();

    assert!(
        report.found,
        "the sweep does not reach where the master key lives, so every absence \
         this file reports is the instrument standing where the evidence is: \
         {report}",
    );

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
/// The two thresholds agree. [`QUIET`] is this crate's own statement that
/// a run of eight bytes is the widest memory throws up by accident. A run of
/// exactly that width, put there deliberately, must therefore not read as
/// accident to the score either. Raise one of the two without the other and
/// this test is what notices.
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
        let key = leak_master_key(WIDE)?;

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
        "{PIECE} bytes of the key read as chance, which is what {QUIET} says \
         they are not: {delta}",
    );

    drop(core::hint::black_box(kept));

    Ok(())
}

/// Opening it once leaves nothing.
///
/// The guard is let go at the end of the block, which is after the capture and
/// before the photograph — so the stack the open used is read as the open left
/// it, and the allocation is read after whatever empties it has run.
#[test]
fn test_opening_the_master_key_once_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let key = capture(|| leak_master_key(WIDE))?;

        drop(key);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "one open");

    Ok(())
}

/// Opening it two hundred times leaves nothing either.
///
/// What the count is for is a piece that survives one open in fifty: it would
/// not show once and shows plainly here. The capture reads the stack as the
/// last open left it, and the photograph reads every allocation the two
/// hundred of them made and gave back.
#[test]
fn test_opening_the_master_key_often_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                let key = leak_master_key(WIDE)?;

                core::hint::black_box(key[0]);
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, &format!("{ROUNDS} opens"));

    Ok(())
}
