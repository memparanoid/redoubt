// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Each conversion borrows the caller's slice as an array; the owning form
//! would copy, and a copy of a key is a second one nothing here empties.
//!
//! Nothing a conversion writes is secret, so the presences find the key where
//! the caller keeps it: what they vouch for is that a copy of that width is
//! something the sweep reads, which is what the absence beside each leans on.

use redoubt_aead_core::consts::{aegis, chacha, poly1305};
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::utils::{aegis_widths, aegis_widths_mut, chacha_widths, chacha_widths_mut};

use crate::tests::forensics::support::{Watching, backwards, giving, is_found};

/// Thirty-two distinct bytes, so a run that extends did not extend by luck.
const CHACHA_KEY: [u8; chacha::KEY_SIZE] = [
    0x3C, 0xA9, 0x15, 0x7E, 0xD2, 0x68, 0xBF, 0x04, 0x91, 0x2D, 0xE6, 0x5B, 0x70, 0xC8, 0x37, 0xAE,
    0x62, 0x1B, 0xF4, 0x89, 0x0D, 0x53, 0xCA, 0x76, 0xE1, 0x38, 0xAF, 0x92, 0x4B, 0xD0, 0x65, 0x1C,
];

/// Sixteen distinct bytes, sharing no run with `CHACHA_KEY`.
const AEGIS_KEY: [u8; aegis::KEY_SIZE] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
];

// ============================================================================
// chacha_widths
// ============================================================================

#[test]
fn test_chacha_widths_finds_the_key_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let mut key = [0_u8; chacha::KEY_SIZE];
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let tag = [0_u8; poly1305::TAG_SIZE];

    giving(&mut key, &CHACHA_KEY);

    forensics!({
        let converted = capture(|| chacha_widths(&key, &nonce, &tag));

        converted.expect("Infallible: the widths are the cipher's own");
    });

    is_found(&watch.snapshot()?, "the key, in the caller's array");

    Ok(())
}

#[test]
fn test_chacha_widths_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &CHACHA_KEY)])?;

    let mut key = [0_u8; chacha::KEY_SIZE];
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let tag = [0_u8; poly1305::TAG_SIZE];

    giving(&mut key, &CHACHA_KEY);

    forensics!({
        let converted = capture(|| chacha_widths(&key, &nonce, &tag));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        converted.expect("Infallible: the widths are the cipher's own");
        key.fast_zeroize();
    });

    watching.none_left("chacha_widths")?;

    Ok(())
}

// ============================================================================
// chacha_widths_mut
// ============================================================================

#[test]
fn test_chacha_widths_mut_finds_the_key_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&CHACHA_KEY))?;

    let mut key = [0_u8; chacha::KEY_SIZE];
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let mut tag = [0_u8; poly1305::TAG_SIZE];

    giving(&mut key, &CHACHA_KEY);

    forensics!({
        let converted = capture(|| chacha_widths_mut(&key, &nonce, &mut tag));

        converted.expect("Infallible: the widths are the cipher's own");
    });

    is_found(&watch.snapshot()?, "the key, in the caller's array");

    Ok(())
}

#[test]
fn test_chacha_widths_mut_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &CHACHA_KEY)])?;

    let mut key = [0_u8; chacha::KEY_SIZE];
    let nonce = [0_u8; chacha::XNONCE_SIZE];
    let mut tag = [0_u8; poly1305::TAG_SIZE];

    giving(&mut key, &CHACHA_KEY);

    forensics!({
        let converted = capture(|| chacha_widths_mut(&key, &nonce, &mut tag));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        converted.expect("Infallible: the widths are the cipher's own");
        key.fast_zeroize();
    });

    watching.none_left("chacha_widths_mut")?;

    Ok(())
}

// ============================================================================
// aegis_widths
// ============================================================================

#[test]
fn test_aegis_widths_finds_the_key_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let mut key = [0_u8; aegis::KEY_SIZE];
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let tag = [0_u8; aegis::TAG_SIZE];

    giving(&mut key, &AEGIS_KEY);

    forensics!({
        let converted = capture(|| aegis_widths(&key, &nonce, &tag));

        converted.expect("Infallible: the widths are the cipher's own");
    });

    is_found(&watch.snapshot()?, "the key, in the caller's array");

    Ok(())
}

#[test]
fn test_aegis_widths_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &AEGIS_KEY)])?;

    let mut key = [0_u8; aegis::KEY_SIZE];
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let tag = [0_u8; aegis::TAG_SIZE];

    giving(&mut key, &AEGIS_KEY);

    forensics!({
        let converted = capture(|| aegis_widths(&key, &nonce, &tag));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        converted.expect("Infallible: the widths are the cipher's own");
        key.fast_zeroize();
    });

    watching.none_left("aegis_widths")?;

    Ok(())
}

// ============================================================================
// aegis_widths_mut
// ============================================================================

#[test]
fn test_aegis_widths_mut_finds_the_key_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&AEGIS_KEY))?;

    let mut key = [0_u8; aegis::KEY_SIZE];
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let mut tag = [0_u8; aegis::TAG_SIZE];

    giving(&mut key, &AEGIS_KEY);

    forensics!({
        let converted = capture(|| aegis_widths_mut(&key, &nonce, &mut tag));

        converted.expect("Infallible: the widths are the cipher's own");
    });

    is_found(&watch.snapshot()?, "the key, in the caller's array");

    Ok(())
}

#[test]
fn test_aegis_widths_mut_leaves_no_key_behind() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &AEGIS_KEY)])?;

    let mut key = [0_u8; aegis::KEY_SIZE];
    let nonce = [0_u8; aegis::NONCE_SIZE];
    let mut tag = [0_u8; aegis::TAG_SIZE];

    giving(&mut key, &AEGIS_KEY);

    forensics!({
        let converted = capture(|| aegis_widths_mut(&key, &nonce, &mut tag));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        converted.expect("Infallible: the widths are the cipher's own");
        key.fast_zeroize();
    });

    watching.none_left("aegis_widths_mut")?;

    Ok(())
}
