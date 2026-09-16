// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What refusing a message leaves of the tag that refused it.
//!
//! # Why the computed tag is the needle
//!
//! Deciphering and computing the tag are the same walk of the state, so
//! `decrypt` has the tag the message deserves before it knows whether to
//! accept it. That value is made from the key and from nothing the caller
//! supplied, and it is the one thing this crate holds in Rust rather than in a
//! register the assembly wipes.
//!
//! # Why the refusal and not the acceptance
//!
//! On the accepting path the caller is holding those same sixteen bytes — it
//! passed them in — so a sweep finding them would have found the caller's copy
//! and said nothing. The refusing path is the one where the computed tag exists
//! nowhere but inside the call.
//!
//! # Only the call goes in the block
//!
//! `forensics!` runs its block a megabyte down the stack so that taking the
//! photograph does not write over what the block left. What it cannot do is
//! protect the block from itself: a buffer allocated inside it is dropped
//! inside it, and `dealloc` is a call whose frame lands exactly on the stack
//! the measured call just released.
//!
//! Sixteen bytes go under that in full. Measured: with the buffer declared
//! inside the block this file reported a clean process against a `decrypt`
//! whose wipe had been deleted, and moving one `let` outside it turned the same
//! test red. So the block holds the call and nothing else — every buffer,
//! every drop and every assertion lives outside it.
//!
//! # Why this is here and not under `tests`
//!
//! The control has to hold the tag across a photograph, and nothing this crate
//! publishes leaves one held: `decrypt` empties it before it returns. What
//! stops one step short is [`crate::asm::decrypt`], which takes the
//! destination by `&mut` and is `pub(crate)`.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the tag could be and another test's needle to trip over. `nextest`,
//! not `cargo test`.

#![cfg(target_os = "linux")]

use std::vec;
use std::{println, vec::Vec};

use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};

use redoubt_aead_v2_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_v2_core::{AeadDecrypt, AeadError};

use crate::aegis128l::Aegis128L;
use crate::asm;

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

/// The ciphertext handed over, and how much of it.
///
/// One size and not a sweep: the tag is sixteen bytes whatever the message was,
/// and the wipe is over an array of that width, so a second length would be the
/// same instruction on the same slot.
const SIZE: usize = 1024;
const FILL: u8 = 0x5A;

/// The tag AEGIS computes for everything above.
///
/// Not chosen: taken. The control below asserts it against what the assembly
/// answers, so a value that stopped being the right one fails there rather than
/// turning every absence in this file into a sweep for bytes nothing ever held.
const TAG: [u8; TAG_SIZE] = [
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

/// The needle, built from its last byte to its first.
fn backwards() -> Vec<u8> {
    TAG.iter().rev().copied().collect()
}

// ============================================================================
// The controls
// ============================================================================

/// The sweep finds the tag when the tag is plainly there.
///
/// The assembly writes it where it is told and stops, which is the one step
/// short of the subject. A test of its own, so the copy it keeps alive is in
/// nobody else's memory.
///
/// It is also what says the constant above is still the tag this key answers:
/// a needle nothing ever held would make every absence in this file free.
#[test]
fn test_the_sweep_finds_the_tag_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut data = vec![FILL; SIZE];
    let mut held = [0_u8; TAG_SIZE];

    asm::decrypt(&KEY, &NONCE, AAD, &mut data, &mut held);
    core::hint::black_box(&held);

    assert_eq!(
        held, TAG,
        "the constant in this file is not the tag the assembly answers"
    );

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the tag, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where a copy lives, so every absence this file \
         reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box((held, data)));

    Ok(())
}

/// A frame left full, which is what the subject would be without its wipe.
///
/// The one the subject rests on. The tag goes into a local of this frame and
/// the frame is left without emptying it, and what the sweep reports here is
/// what it would report of `decrypt` if the wipe were deleted — so the day this
/// reads clean, the subject below has stopped measuring and says so here first.
#[inline(never)]
fn a_frame_left_full(data: &mut [u8]) {
    let mut expected = [0_u8; TAG_SIZE];

    asm::decrypt(&KEY, &NONCE, AAD, data, &mut expected);

    core::hint::black_box(&expected);
}

#[test]
fn test_the_sweep_finds_the_tag_in_a_frame_that_was_left_full() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;
    let mut data = vec![FILL; SIZE];

    let report = forensics!(watch, {
        a_frame_left_full(&mut data);
    });

    println!();
    report.summary("a frame left full");
    println!();

    drop(core::hint::black_box(data));

    assert!(
        report.found,
        "the sweep does not reach a frame that was left, so the absence the \
         subject reports is the stack being reused and not the wipe: {report}"
    );

    Ok(())
}

// ============================================================================
// Aegis128L::decrypt
// ============================================================================

/// A refusal gives the tag up with the plaintext.
///
/// What the call computes is the needle and what the caller holds is not, so an
/// absence afterwards is about the call.
#[test]
fn test_a_refusal_leaves_no_tag_a_sweep_can_find() -> Result<(), AnyError> {
    let mut aead = Aegis128L::new();
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing decrypted yet");

    let mut data = vec![FILL; SIZE];
    let mut refused = Ok(());

    let report_after = forensics!(watch, {
        refused = aead.decrypt(&KEY, &NONCE, AAD, &mut data, &WRONG);
    });

    report_after.summary_against(&report_before, "a message refused");
    println!();

    drop(core::hint::black_box(data));

    assert_eq!(refused, Err(AeadError::AuthenticationFailed));

    assert!(
        !report_after.found,
        "the tag it computed survived the refusal: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived the refusal, and {QUIET} is what memory has \
         by accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(&report_before);

    assert!(delta.is_noise(), "the refusal moved the score: {delta}");

    Ok(())
}
