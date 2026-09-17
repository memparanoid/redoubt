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
//! A control has to find the secret where the operation puts it, so reaching
//! one step short of the public surface is the only way to have one here at
//! all.
//!
//! # Which backend
//!
//! Whichever the target has. On one with no assembly the arithmetic is the
//! compiler's and so are the registers it passes through, and nothing here is
//! a claim about those.
//!
//! # One size per test
//!
//! The sweep reads the whole process, so a size that leaks leaves the pad in
//! memory and every size measured after it in the same process finds that copy
//! and is blamed for it. Under `nextest` each test is a process of its own, so
//! the size that failed is the name of the test that failed.
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

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, elenchos};
use redoubt_poly1305::Poly1305;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::xchachapoly1305::XChaCha20Poly1305;

/// A one-time key whose pad half is sixteen distinct bytes: no value repeats,
/// so a run that extends did not extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const ONE_TIME_KEY: [u8; KEY_SIZE] = [
    0x3C, 0xA9, 0x15, 0x7E, 0xD2, 0x68, 0xBF, 0x04, 0x91, 0x2D, 0xE6, 0x5B, 0x70, 0xC8, 0x37, 0xAE,
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
];

/// What the authenticator is told the ciphertext was sent with.
const AAD: &[u8] = b"associated data, long enough to owe a padding block";

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards() -> Vec<u8> {
    ONE_TIME_KEY[BLOCK_SIZE..].iter().rev().copied().collect()
}

/// The photograph says the pad is there, which is what makes the absences
/// below mean anything.
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
/// The whole pad is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("no tag taken yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole pad survived {what}: {report_after}"
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
// XChaCha20Poly1305::tag_with
// ============================================================================

/// The pad is found while the authenticator is still holding it.
///
/// An authenticator told everything and asked nothing is still holding it, and
/// that is one step short of every absence below. Nothing is planted: what the
/// sweep finds is the authenticator's own state, where the pad has been since
/// it was built.
#[test]
fn test_the_pad_is_found_while_the_authenticator_holds_it() -> Result<(), AnyError> {
    let aead = XChaCha20Poly1305::new();
    let mut watch = Forensics::watching(&backwards())?;

    let ciphertext = vec![0x5A_u8; 1024];
    let mut held = Poly1305::new(&ONE_TIME_KEY);

    elenchos!({
        aead.tag_with(&mut held, AAD, &ciphertext);

        capture!();

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the pad, still in the authenticator");

    drop(core::hint::black_box((ciphertext, aead)));

    Ok(())
}

/// A tag taken over one size, and the pad given up with it.
macro_rules! a_tag_taken {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let aead = XChaCha20Poly1305::new();
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let ciphertext = vec![0x5A_u8; $of];
            let mut authenticator = Poly1305::new(&ONE_TIME_KEY);
            let mut tag = [0_u8; TAG_SIZE];

            elenchos!({
                aead.tag_with(&mut authenticator, AAD, &ciphertext);
                authenticator.finalize_mut(&mut tag);

                capture!();
            });

            drop(core::hint::black_box((authenticator, ciphertext, tag)));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a tag taken over {} bytes", $of),
            );

            drop(core::hint::black_box(aead));

            Ok(())
        }
    };
}

a_tag_taken!(test_a_tag_over_no_bytes_leaves_nothing, 0);
a_tag_taken!(test_a_tag_over_1_byte_leaves_nothing, 1);
a_tag_taken!(test_a_tag_over_15_bytes_leaves_nothing, 15);
a_tag_taken!(test_a_tag_over_16_bytes_leaves_nothing, 16);
a_tag_taken!(test_a_tag_over_17_bytes_leaves_nothing, 17);
a_tag_taken!(test_a_tag_over_1024_bytes_leaves_nothing, 1024);
a_tag_taken!(test_a_tag_over_16384_bytes_leaves_nothing, 16384);
