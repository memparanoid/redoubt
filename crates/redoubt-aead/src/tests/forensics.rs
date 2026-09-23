// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the conversion from a slice leaves of the key it was handed.
//!
//! # Why this one is not in `tests/`
//!
//! The functions it is about are `pub(crate)`. Nothing this crate publishes
//! reaches them, so a file outside could not call the operation at all.
//!
//! # Why the key is the needle
//!
//! `<&[u8; N]>::try_from` reads a length and borrows. The owning form copies,
//! and a copy of a key is a second one that nothing here is in a position to
//! empty — the caller wipes what it declared and the copy stays where the
//! conversion put it.
//!
//! The pointer comparison beside these settles the same question from inside
//! the process and settles it deterministically. This settles it from outside,
//! over the whole of the process's memory, which is where a copy would be if
//! there were one.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place a key could be and another test's needle to trip over. `nextest`, not
//! `cargo test`.

#![cfg(target_os = "linux")]

use alloc::vec::Vec;

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
use redoubt_zero::FastZeroizable;

use redoubt_aead_core::consts::{aegis, chacha, poly1305};

use crate::utils::{aegis_widths, aegis_widths_mut, chacha_widths, chacha_widths_mut};

/// Distinct bytes, so that a run which extends did not extend by luck.
///
/// `const`, so the bytes the test itself holds live where the sweep does not
/// read them as a copy. What is measured is the array made from this one.
const CHACHA_KEY: [u8; chacha::KEY_SIZE] = [
    0x3C, 0xA9, 0x15, 0x7E, 0xD2, 0x68, 0xBF, 0x04, 0x91, 0x2D, 0xE6, 0x5B, 0x70, 0xC8, 0x37, 0xAE,
    0x62, 0x1B, 0xF4, 0x89, 0x0D, 0x53, 0xCA, 0x76, 0xE1, 0x38, 0xAF, 0x92, 0x4B, 0xD0, 0x65, 0x1C,
];

/// Distinct bytes again, and sharing no run with the wider key.
const AEGIS_KEY: [u8; aegis::KEY_SIZE] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
];

/// A needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards(key: &[u8]) -> Vec<u8> {
    key.iter().rev().copied().collect()
}

/// The photograph says the key is there, which is what makes an absence mean
/// anything.
fn is_found(report: &Report, what: &str) {
    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence resting on it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// The three things an absence has to survive.
///
/// The whole key is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(before: &Report, after: &Report, what: &str) {
    // Assert zeroization!
    assert!(!after.found, "the whole key survived {what}: {after}");

    assert!(
        after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {after}",
        after.widest,
    );

    let delta = after.against(before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// chacha_widths
// ============================================================================

/// The sweep can find a key of this width where the caller keeps one.
///
/// It says nothing about the conversion — the key is there because the caller's
/// array is, and would be with no call at all. What it establishes is that a
/// copy of this width in this process is something the instrument reads, which
/// is what an absence of this key rests on.
#[test]
fn test_chacha_widths_finds_the_key_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let key = CHACHA_KEY;
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let tag = [0_u8; poly1305::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            chacha_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own")
        });

        core::hint::black_box(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key, in the caller's array");

    core::hint::black_box(&key);

    Ok(())
}

/// A conversion that copied would leave that copy standing after the wipe.
///
/// What the caller declared is emptied, and the sweep reads the whole of the
/// process rather than the array.
#[test]
fn test_chacha_widths_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let before = watch.snapshot()?;

    let mut key = CHACHA_KEY;
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let tag = [0_u8; poly1305::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            chacha_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own")
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        core::hint::black_box(held);
        key.fast_zeroize();
    });

    let after = watch.snapshot()?;

    leaves_nothing(&before, &after, "a key converted");

    Ok(())
}

// ============================================================================
// chacha_widths_mut
// ============================================================================

/// The sweep can find a key of this width where the caller keeps one.
///
/// It says nothing about the conversion — the key is there because the caller's
/// array is, and would be with no call at all. What it establishes is that a
/// copy of this width in this process is something the instrument reads, which
/// is what an absence of this key rests on.
#[test]
fn test_chacha_widths_mut_finds_the_key_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let key = CHACHA_KEY;
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let mut tag = [0_u8; poly1305::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            chacha_widths_mut(&key, &nonce, &mut tag)
                .expect("Infallible: the widths are the cipher's own")
        });

        core::hint::black_box(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key, in the caller's array");

    core::hint::black_box(&key);

    Ok(())
}

#[test]
fn test_chacha_widths_mut_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let before = watch.snapshot()?;

    let mut key = CHACHA_KEY;
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let mut tag = [0_u8; poly1305::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            chacha_widths_mut(&key, &nonce, &mut tag)
                .expect("Infallible: the widths are the cipher's own")
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        core::hint::black_box(held);
        key.fast_zeroize();
    });

    let after = watch.snapshot()?;

    leaves_nothing(&before, &after, "a key converted for a tag to be written");

    Ok(())
}

// ============================================================================
// aegis_widths
// ============================================================================

/// The sweep can find a key of this width where the caller keeps one.
///
/// Sixteen bytes is still wider than what memory has by accident, and a
/// conversion that borrowed one width and copied the other would pass every
/// case about the wider key and fail here.
#[test]
fn test_aegis_widths_finds_the_key_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let key = AEGIS_KEY;
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let tag = [0_u8; aegis::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            aegis_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own")
        });

        core::hint::black_box(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the aegis key, in the caller's array");

    core::hint::black_box(&key);

    Ok(())
}

#[test]
fn test_aegis_widths_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let before = watch.snapshot()?;

    let mut key = AEGIS_KEY;
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let tag = [0_u8; aegis::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            aegis_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own")
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        core::hint::black_box(held);
        key.fast_zeroize();
    });

    let after = watch.snapshot()?;

    leaves_nothing(&before, &after, "an aegis key converted");

    Ok(())
}

// ============================================================================
// aegis_widths_mut
// ============================================================================

/// The sweep can find a key of this width where the caller keeps one.
///
/// Sixteen bytes is still wider than what memory has by accident, and a
/// conversion that borrowed one width and copied the other would pass every
/// case about the wider key and fail here.
#[test]
fn test_aegis_widths_mut_finds_the_key_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let key = AEGIS_KEY;
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let mut tag = [0_u8; aegis::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            aegis_widths_mut(&key, &nonce, &mut tag)
                .expect("Infallible: the widths are the cipher's own")
        });

        core::hint::black_box(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the aegis key, in the caller's array");

    core::hint::black_box(&key);

    Ok(())
}

#[test]
fn test_aegis_widths_mut_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let before = watch.snapshot()?;

    let mut key = AEGIS_KEY;
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let mut tag = [0_u8; aegis::TAG_SIZE];

    forensics!({
        let held = capture(|| {
            aegis_widths_mut(&key, &nonce, &mut tag)
                .expect("Infallible: the widths are the cipher's own")
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        core::hint::black_box(held);
        key.fast_zeroize();
    });

    let after = watch.snapshot()?;

    leaves_nothing(
        &before,
        &after,
        "an aegis key converted for a tag to be written",
    );

    Ok(())
}
