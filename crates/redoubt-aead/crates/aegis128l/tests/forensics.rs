// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a call leaves of the tag it answered with.
//!
//! # Why the tag is the needle
//!
//! Deciphering and computing the tag are the same walk of the state, so
//! `decrypt` has the tag the message deserves before it knows whether to accept
//! it. That value is made from the key and from nothing the caller supplied,
//! and it is the one thing this crate holds in Rust rather than in a register
//! the assembly wipes.
//!
//! # One size
//!
//! The tag is sixteen bytes whatever the message was, and the wipe is over an
//! array of that width, so a second length would be the same instruction on the
//! same slot.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place a tag could be and another test's needle to trip over. `nextest`, not
//! `cargo test`.

#![cfg(all(target_os = "linux", aegis128l_asm))]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
use redoubt_zero::FastZeroizable;

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt, AeadError};

use redoubt_aead_aegis128l::Aegis128L;

/// Sixteen distinct bytes each, so that a run which extends did not extend by
/// luck.
///
/// `const`, so they live where nothing can write and the sweep never reads one
/// as a copy.
const KEY: [u8; KEY_SIZE] = [
    0x3C, 0xA9, 0x15, 0x7E, 0xD2, 0x68, 0xBF, 0x04, 0x91, 0x2D, 0xE6, 0x5B, 0x70, 0xC8, 0x37, 0xAE,
];

const NONCE: [u8; NONCE_SIZE] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
];

/// What the message is said to have been sent with.
const AAD: &[u8] = b"associated data, long enough to owe a padding block";

/// The message handed over, and how much of it.
const SIZE: usize = 1024;
const FILL: u8 = 0x5A;

/// The tag AEGIS seals everything above with.
///
/// Not chosen: taken. The presence in its section asserts it against what the
/// call answers, so a value that stopped being the right one fails there rather
/// than turning the absence under it into a sweep for bytes nothing ever held.
const SEALED_TAG: [u8; TAG_SIZE] = [
    0xD6, 0x77, 0xF2, 0x49, 0x65, 0xF2, 0x5E, 0x4C, 0x04, 0x61, 0x2C, 0x62, 0x9C, 0xC3, 0x50, 0x5E,
];

/// The tag AEGIS computes for the same bytes read as a ciphertext.
///
/// A different question from the one above and so a different answer: there the
/// message is enciphered and counted, here it is deciphered and counted.
///
/// What says it is still the right value is the accepting path, which refuses
/// anything else.
const COMPUTED_TAG: [u8; TAG_SIZE] = [
    0x6C, 0x6D, 0xB0, 0x08, 0xD9, 0x2A, 0xC3, 0xE9, 0x9B, 0xF1, 0x62, 0xB5, 0x53, 0x88, 0xAB, 0xF3,
];

/// The tag handed over instead, sharing no run with the one above.
///
/// Not the right tag with a bit turned over, which is the near miss an attacker
/// would send and which `tests::aegis128l` asks for. Sixteen bytes differing in
/// one of them sit in the caller's memory as fifteen bytes of the needle, and
/// the sweep reports that as a fifteen-byte run surviving the call — which is
/// the caller's own buffer and says nothing about what `decrypt` left.
const WRONG: [u8; TAG_SIZE] = [
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards(tag: &[u8; TAG_SIZE]) -> Vec<u8> {
    tag.iter().rev().copied().collect()
}

/// The photograph says the tag is there, which is what makes the absences under
/// it mean anything.
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
/// The whole tag is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, before: &str, what: &str) {
    println!();
    report_before.summary(before);
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole tag survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// Aegis128L::encrypt
// ============================================================================

/// The tag is found while the caller still holds it.
///
/// Nothing is planted: what the sweep finds is the array the call wrote into,
/// where the tag has been since it returned.
#[test]
fn test_the_sealing_tag_is_found_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut aead = Aegis128L::new();
    let mut watch = Forensics::watching(&backwards(&SEALED_TAG))?;

    let mut data = vec![FILL; SIZE];
    let mut tag = [0_u8; TAG_SIZE];

    forensics!({
        aead.encrypt(&KEY, &NONCE, AAD, &mut data, &mut tag);

        capture!();

        core::hint::black_box(&tag);
    });

    assert_eq!(
        tag, SEALED_TAG,
        "the constant in this file is not the tag the call seals with"
    );

    let report = watch.snapshot()?;

    is_found(&report, "the sealing tag, in the caller's array");

    drop(core::hint::black_box((data, tag)));

    Ok(())
}

/// A message sealed, and the tag gone once the caller lets go of it.
#[test]
fn test_a_sealed_message_leaves_no_tag_behind() -> Result<(), AnyError> {
    let mut aead = Aegis128L::new();
    let mut watch = Forensics::watching(&backwards(&SEALED_TAG))?;

    let report_before = watch.snapshot()?;

    let mut data = vec![FILL; SIZE];
    let mut tag = [0_u8; TAG_SIZE];

    forensics!({
        aead.encrypt(&KEY, &NONCE, AAD, &mut data, &mut tag);

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        tag.fast_zeroize();
    });

    drop(core::hint::black_box(data));

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing sealed yet",
        "a message sealed",
    );

    Ok(())
}

// ============================================================================
// Aegis128L::decrypt
// ============================================================================

/// A refusal gives the computed tag up with the plaintext.
///
/// What the call computes is the needle and what the caller handed in is not, so
/// the absence is about the call alone.
#[test]
fn test_a_refused_message_leaves_no_computed_tag_behind() -> Result<(), AnyError> {
    let mut aead = Aegis128L::new();
    let mut watch = Forensics::watching(&backwards(&COMPUTED_TAG))?;

    let report_before = watch.snapshot()?;

    let mut data = vec![FILL; SIZE];
    let refused;

    forensics!({
        refused = aead.decrypt(&KEY, &NONCE, AAD, &mut data, &WRONG);

        capture!();
    });

    drop(core::hint::black_box(data));

    let report_after = watch.snapshot()?;

    assert_eq!(refused, Err(AeadError::AuthenticationFailed));

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing decrypted yet",
        "a message refused",
    );

    Ok(())
}

/// The accepting path gives it up too.
///
/// Here the caller handed in the same sixteen bytes, so its own copy goes after
/// the photograph and what the absence is left with is the call's.
///
/// The `Ok` is also what says the needle is real: a constant that stopped being
/// the tag this key computes is refused here.
#[test]
fn test_an_accepted_message_leaves_no_computed_tag_behind() -> Result<(), AnyError> {
    let mut aead = Aegis128L::new();
    let mut watch = Forensics::watching(&backwards(&COMPUTED_TAG))?;

    let report_before = watch.snapshot()?;

    let mut data = vec![FILL; SIZE];
    let mut given = COMPUTED_TAG;
    let accepted;

    forensics!({
        accepted = aead.decrypt(&KEY, &NONCE, AAD, &mut data, &given);

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        given.fast_zeroize();
    });

    drop(core::hint::black_box(data));

    let report_after = watch.snapshot()?;

    assert_eq!(accepted, Ok(()));

    leaves_nothing(
        &report_before,
        &report_after,
        "nothing decrypted yet",
        "a message accepted",
    );

    Ok(())
}
