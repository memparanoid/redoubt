// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::boxed::Box;

use redoubt_aead_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE};
use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::hchacha20::HChaCha20;

use crate::tests::forensics::support::needles::{KEY, a_key};
use crate::tests::forensics::support::{Watching, backwards, is_found};

/// Public, and so not watched.
const HNONCE: [u8; HNONCE_SIZE] = *b"a nonce, sixteen";

/// The subkey `KEY` and `HNONCE` derive.
///
/// Printed once by a generator, not committed, that held the Rust backend and
/// the assembly to the same bytes.
const SUBKEY: [u8; KEY_SIZE] = [
    0x0F, 0xDB, 0x30, 0xA6, 0x5E, 0xC1, 0x7E, 0x82, 0xF4, 0x4A, 0xA8, 0x35, 0x83, 0xFF, 0x43, 0x84,
    0x97, 0x3B, 0xAA, 0xB6, 0x6C, 0x69, 0x66, 0x91, 0xAA, 0xC1, 0xB4, 0xE9, 0xC8, 0x4C, 0x57, 0x25,
];

// ============================================================================
// HChaCha20::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it holds nothing."]
fn test_making_one_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// HChaCha20::subkey
// ============================================================================

#[test]
fn test_what_subkey_wrote_is_found_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&SUBKEY))?;

    let mut key = a_key();

    forensics!({
        let derivation = HChaCha20::new();

        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let out = Box::leak(Box::new([0_u8; KEY_SIZE]));

        capture(|| derivation.subkey(Backend::default(), out, &key, &HNONCE));

        key.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a subkey derived, and kept");

    Ok(())
}

#[test]
fn test_subkey_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &KEY), ("subkey", &SUBKEY)])?;

    let mut key = a_key();

    forensics!({
        let derivation = HChaCha20::new();
        let mut out = [0_u8; KEY_SIZE];

        capture(|| derivation.subkey(Backend::default(), &mut out, &key, &HNONCE));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The key and the subkey are the caller's.
        key.fast_zeroize();
        out.fast_zeroize();
    });

    watching.none_left("subkey")?;

    Ok(())
}
