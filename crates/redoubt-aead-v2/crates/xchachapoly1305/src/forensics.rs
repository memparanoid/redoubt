// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What taking a tag leaves of the key that answered it.
//!
//! # Why the pad is the needle
//!
//! Poly1305's key is a pair, and the half added at the end is kept byte for
//! byte. It is the one thing in an authenticator that is still the caller's
//! bytes rather than something derived from them, so a copy of it anywhere is
//! a copy of half the one-time key.
//!
//! # Why this is here and not under `tests`
//!
//! An authenticator cannot be caught holding its pad through what this crate
//! publishes: asking for the tag empties it, and so does dropping it. What
//! leaves one full is being told everything and asked nothing, which is
//! `tag_with`, and that is `pub(crate)`.
//!
//! # Which backend
//!
//! Whichever the target has. On one with no assembly the arithmetic is the
//! compiler's and so are the registers it passes through, and nothing here is
//! a claim about those.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the pad could be and another test's needle to trip over. `nextest`,
//! not `cargo test`.

#![cfg(target_os = "linux")]

use std::vec;
use std::vec::Vec;
use std::{format, println};

use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_poly1305::Poly1305;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::xchachapoly1305::XChaCha20Poly1305;

/// A one-time key whose pad half is sixteen distinct bytes: no value repeats,
/// so a run that extends did not extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const ONE_TIME_KEY: [u8; KEY_SIZE] = [
    0x3C, 0xA9, 0x15, 0x7E, 0xD2, 0x68, 0xBF, 0x04, 0x91, 0x2D, 0xE6, 0x5B, 0x70, 0xC8, 0x37, 0xAE,
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
];

/// What the authenticator is told the ciphertext was sent with.
const AAD: &[u8] = b"associated data, long enough to owe a padding block";

/// Every size worth asking about: none, short of a block, a block exactly, and
/// then past anything one call buffers.
///
/// The pad is multiplied in once per block, so one block and a thousand are the
/// same code taking a different number of trips through the same registers.
const SIZES: [usize; 7] = [0, 1, 15, 16, 17, 1024, 16384];

/// The needle, built from its last byte to its first.
fn backwards() -> Vec<u8> {
    ONE_TIME_KEY[BLOCK_SIZE..].iter().rev().copied().collect()
}

/// Everything a caller must be able to say about what an operation left, at
/// every size.
fn leaves_nothing_at_any_size(
    what: &str,
    mut work: impl FnMut(&XChaCha20Poly1305, usize),
) -> Result<(), AnyError> {
    // Built before the first photograph: what is being asked about is what
    // taking a tag leaves, not what building the construction leaves.
    let aead = XChaCha20Poly1305::new();
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("no tag taken yet");

    for of in SIZES {
        let report_after = forensics!(watch, { work(&aead, of) });

        report_after.summary_against(&report_before, &format!("{what}, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole pad survived {what} of {of} bytes: {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived {what} of {of} bytes, and {QUIET} is what \
             memory has by accident: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "{what} of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    drop(core::hint::black_box(aead));

    Ok(())
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the pad when the pad is plainly there.
///
/// An authenticator told everything and asked nothing is still holding it, and
/// that is the one step short of the test below. A test of its own, so the copy
/// it keeps alive is in nobody else's memory.
#[test]
fn test_the_sweep_finds_the_pad_while_it_is_held() -> Result<(), AnyError> {
    let aead = XChaCha20Poly1305::new();
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = Poly1305::new(&ONE_TIME_KEY);
    let ciphertext = vec![0x5A_u8; 1024];

    aead.tag_with(&mut held, AAD, &ciphertext);
    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the pad, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where a copy lives, so every absence this file \
         reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box((held, ciphertext, aead)));

    Ok(())
}

// ============================================================================
// XChaCha20Poly1305::tag_with
// ============================================================================

/// Asked for the tag, the authenticator gives the pad up with it.
#[test]
fn test_taking_a_tag_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("a tag taken over", |aead, of| {
        let ciphertext = vec![0x5A_u8; of];
        let mut authenticator = Poly1305::new(&ONE_TIME_KEY);
        let mut tag = [0_u8; TAG_SIZE];

        aead.tag_with(&mut authenticator, AAD, &ciphertext);
        authenticator.finalize_mut(&mut tag);

        drop(core::hint::black_box((authenticator, ciphertext, tag)));
    })
}
