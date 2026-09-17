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
//! # The needle is never turned around in place
//!
//! `reverse()` on a slice is an exchange, and an exchange of a value this size
//! is a handful of vector registers. Doing it to the buffer would leave half
//! the value in them and the test would be measuring itself. It is read
//! backwards into a second allocation instead, one byte at a time.
//!
//! # And what a failure here would mean
//!
//! Not that `getrandom` is broken. That the bytes it produced are reachable in
//! this process after the only buffer holding them was cleared, which is a
//! property of the path and not of the randomness.

// Every measurement in this file was taken with an instrument that could not
// see past a call made after the operation, so each absence it reports is
// worth less than it says. Kept unbuilt, and only until `elenchos.rs` covers
// what it covered.
#![cfg(any())]

use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_rand::{EntropySource, SystemEntropySource};

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

/// Bytes from the system, and the same bytes read from last to first.
///
/// The second is the needle. The sweep looks for it reversed, which is the
/// first — so the needle itself never matches, and the only thing that can is
/// a copy of what the system produced.
fn asked_for(of: usize) -> Result<(Vec<u8>, Vec<u8>), AnyError> {
    let mut got = vec![0_u8; of];

    SystemEntropySource {}.fill_bytes(&mut got)?;

    let needle = got.iter().rev().copied().collect();

    Ok((got, needle))
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the bytes while the buffer still holds them.
///
/// Every absence this file reports is worth exactly what this is worth: a
/// sweep that reached nowhere would report the same absence for a process
/// holding the value in plain sight.
#[test]
fn test_the_sweep_finds_the_entropy_while_it_is_held() -> Result<(), AnyError> {
    let (held, needle) = asked_for(WIDE)?;

    let mut watch = Forensics::watching(&needle)?;

    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the entropy, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where the bytes landed, so every absence this \
         file reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    core::hint::black_box(&held);

    Ok(())
}

// ============================================================================
// SystemEntropySource::fill_bytes
// ============================================================================

/// Nothing of what the system produced is reachable once the buffer is
/// cleared.
///
/// # The first photograph is the control
///
/// It is taken while the buffer still holds the bytes, so it must find them.
/// That is what makes the second one worth reading, and it says it about
/// *this* process rather than about some other test's.
///
/// The wipe runs inside the macro so that the register file is captured with
/// it. A bare `snapshot` reads memory alone, and a value that came back from a
/// syscall is exactly the kind that would be sitting in a register.
#[test]
fn test_asking_for_entropy_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let (mut got, needle) = asked_for(WIDE)?;

    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, { wipe(&mut got) });

    println!();
    report_before.summary("asked for, and still held");
    report_after.summary_against(&report_before, "the buffer wiped");
    println!();

    assert!(
        report_before.found,
        "the sweep does not reach where the bytes landed, so the absence below \
         is the instrument and not the code: {report_before}",
    );

    assert!(
        !report_after.found,
        "the whole of what the system produced is still in this process after \
         the only buffer holding it was cleared: {report_after}",
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes of it survived, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    core::hint::black_box(&got);

    Ok(())
}

/// The same, two hundred times over.
///
/// Each round asks for its own bytes and wipes them, and the needle is the
/// first round's. A path that keeps the last value would show at one round;
/// one that keeps a piece of an older one shows only here.
#[test]
fn test_two_hundred_requests_leave_nothing_of_the_first() -> Result<(), AnyError> {
    let (mut got, needle) = asked_for(WIDE)?;

    wipe(&mut got);

    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        for _ in 0..ROUNDS {
            let mut round = vec![0_u8; WIDE];

            SystemEntropySource {}.fill_bytes(&mut round)?;

            wipe(&mut round);

            drop(core::hint::black_box(round));
        }

        Ok::<(), AnyError>(())
    });

    println!();
    report_before.summary("asked for once, and wiped");
    report_after.summary_against(&report_before, &format!("{ROUNDS} more requests"));
    println!();

    assert!(
        !report_after.found,
        "the first value surfaced after {ROUNDS} later requests: {report_after}",
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "{ROUNDS} requests moved the score: {delta}"
    );

    core::hint::black_box(&got);

    Ok(())
}
