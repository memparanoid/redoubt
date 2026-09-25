// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What asking the operating system for entropy leaves behind.
//!
//! # Why this is measured backwards from everything else
//!
//! Every other sweep in this workspace starts from a secret it chose and
//! watches an operation move it. There is no choosing here: the value does not
//! exist until the call that produces it, so there is nothing to watch *for*
//! beforehand.
//!
//! So the order is inverted. The bytes are asked for, the needle is built from
//! what arrived, the buffer they arrived in is wiped, and only then is the
//! question put. Whatever the sweep finds after that was left by the path the
//! bytes travelled — the syscall's return, the library that wrapped it, a
//! register on the way out — and not by anything still holding them.
//!
//! # What the inversion costs, and it is the register half
//!
//! The instrument cannot exist before the call, because the needle comes out of
//! it. So the freeze is never adjacent to the ask: what it reads are the
//! registers as the **wipe** left them, and between the ask and the wipe there
//! ran a loop building the needle and the whole of `Forensics::watching`.
//!
//! A value still sitting in a register from the syscall's return will be found
//! if nothing in between happened to use that register, and missed if something
//! did. That is weaker than everywhere else in this workspace, it cannot be
//! made stronger for a value nobody may choose, and it is why the absences here
//! are read as claims about **memory** first.
//!
//! # The needle is never turned around in place
//!
//! `reverse()` on a slice is an exchange, and an exchange of a value this size
//! is a handful of vector registers. Doing it to the buffer would leave half
//! the value in them and the test would be measuring itself. It is read
//! backwards into a second allocation instead, one byte at a time.
//!
//! # What a failure here would mean
//!
//! Not that `getrandom` is broken. That the bytes it produced are reachable in
//! this process after the only buffer holding them was cleared, which is a
//! property of the path and not of the randomness.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics, freeze};
use redoubt_rand::{EntropySource, SystemEntropySource, fill_with_random_bytes};

/// As much as a key is, which is the length that matters.
const WIDE: usize = 32;

/// One round leaving nothing is a weaker claim than it looks.
///
/// A piece that survives one call in fifty would not show once and would show
/// plainly at two hundred.
const ROUNDS: usize = 200;

/// Every byte of it back to zero, so that what survives is not memory.
///
/// Volatile and one at a time: a `fill` is a call to `memset`, which would put
/// the value through the very registers this is asking about.
fn wipe(into: &mut [u8]) {
    for at in 0..into.len() {
        // SAFETY: in bounds of a live slice.
        unsafe { into.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// The same bytes read from last to first, into an allocation of their own.
///
/// This is the needle. The sweep looks for it reversed, which is the value
/// itself — so the needle never matches, and the only thing that can is a copy
/// of what the call produced.
fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// The photograph says the value is there, which is what makes the absence
/// beside it mean anything.
fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// The three things an absence has to survive.
///
/// The whole value is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, before: &str, report_after: &Report, what: &str) {
    println!();
    report_before.summary(before);
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole of what the call produced is still in this process after \
         {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes of it survived {what}, and {QUIET} is what memory \
         has by accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// fill_with_random_bytes
// ============================================================================

/// What the call produced is found while the buffer still holds it.
///
/// The presence every absence in this file leans on, and the one place it can
/// be taken: the buffer the caller handed in, which is where the bytes landed.
///
/// # Why the block has only a capture in it
///
/// The ask cannot go inside: the needle comes out of it, so the instrument
/// does not exist until afterwards. What the block is for is the shape — the
/// absence beside this one reads three places, the registers and the copied
/// window and live memory, and a presence that read only the third would not
/// vouch for the other two.
#[test]
fn test_what_was_asked_for_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    fill_with_random_bytes(&mut got)?;

    let mut watch = Forensics::watching(&backwards(&got))?;

    forensics!({
        freeze!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "the bytes, still in the buffer");

    wipe(&mut got);

    drop(core::hint::black_box(got));

    Ok(())
}

/// Nothing of what the call produced is reachable once the buffer is cleared.
#[test]
fn test_asking_for_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    fill_with_random_bytes(&mut got)?;

    let mut watch = Forensics::watching(&backwards(&got))?;

    let report_before = watch.snapshot()?;

    forensics!({
        capture(|| wipe(&mut got));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "asked for, and still held",
        &report_after,
        "the buffer wiped",
    );

    drop(core::hint::black_box(got));

    Ok(())
}

/// Two hundred later requests leave nothing of the first.
///
/// Each round asks for its own bytes and wipes them, and the needle is the
/// first round's. A path that keeps the last value would show at one round; one
/// that keeps a piece of an older one shows only here.
#[test]
fn test_two_hundred_requests_leave_nothing_of_the_first() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    fill_with_random_bytes(&mut got)?;

    let needle = backwards(&got);

    wipe(&mut got);

    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                let mut round = vec![0_u8; WIDE];

                fill_with_random_bytes(&mut round)?;

                wipe(&mut round);

                drop(round);
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "asked for once, and wiped",
        &report_after,
        &format!("{ROUNDS} more requests"),
    );

    drop(core::hint::black_box(got));

    Ok(())
}

// ============================================================================
// SystemEntropySource::fill_bytes
// ============================================================================

/// What the source produced is found while the buffer still holds it.
#[test]
fn test_what_the_source_produced_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    SystemEntropySource {}.fill_bytes(&mut got)?;

    let mut watch = Forensics::watching(&backwards(&got))?;

    forensics!({
        freeze!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "the bytes, still in the buffer");

    wipe(&mut got);

    drop(core::hint::black_box(got));

    Ok(())
}

/// Nothing of it is reachable once the buffer is cleared.
///
/// Its own section rather than one more test above, because this is the path a
/// caller holding an `EntropySource` takes: the trait method wraps the same
/// syscall in a check of its own, and the wrapper is code that could keep
/// something.
#[test]
fn test_asking_the_source_leaves_nothing() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    SystemEntropySource {}.fill_bytes(&mut got)?;

    let mut watch = Forensics::watching(&backwards(&got))?;

    let report_before = watch.snapshot()?;

    forensics!({
        capture(|| wipe(&mut got));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "asked for, and still held",
        &report_after,
        "the buffer wiped",
    );

    drop(core::hint::black_box(got));

    Ok(())
}
