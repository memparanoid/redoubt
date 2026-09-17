// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encrypting a secret leaves behind.
//!
//! # Why the buffer is not the question
//!
//! Encryption is in place: when it returns, the buffer holds ciphertext and
//! the plaintext is gone from it by construction. So anything the sweep finds
//! afterwards was left somewhere else — a register the routine moved the
//! plaintext through, or a stack slot the compiler spilled one into.
//!
//! That is the whole of what is being asked here, and it is asked at every
//! size because a cipher processes its input in blocks: one block and a
//! thousand blocks are the same code taking a different number of trips
//! through the same registers.
//!
//! # Which backend
//!
//! Whichever [`Aead::new`] picks for this machine. On `x86_64` with AES-NI
//! that is the AEGIS-128L assembly, which is the one worth measuring — the
//! portable fallback moves the same bytes through registers the compiler
//! chose rather than ones somebody wrote down.

// Every measurement in this file was taken with an instrument that could not
// see past a call made after the operation, so each absence it reports is
// worth less than it says. Kept unbuilt: this crate is the one being replaced,
// and rewriting its measurements against the new instrument is work that goes
// with whatever replaces it.
#![cfg(any())]

use redoubt_aead::Aead;
use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_zero::FastZeroizable;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Every size worth asking about, from one block up to where the cipherbox
/// above started leaving the secret in plain sight.
const SIZES: [usize; 8] = [32, 64, 128, 512, 1024, 4096, 16384, 32768];

/// The needle, built from its last byte to its first.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The secret over and over, by the copy that erases what it used, so that
/// filling the source is not itself the leak.
fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// Everything a caller must be able to say about what an operation left, at
/// every size.
fn leaves_nothing_at_any_size(
    what: &str,
    mut work: impl FnMut(&mut Aead, usize) -> Result<(), AnyError>,
) -> Result<(), AnyError> {
    // Built before the first photograph: what is being asked about is what
    // encrypting leaves, not what choosing a backend leaves.
    let mut aead = Aead::new();
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing encrypted yet");

    for of in SIZES {
        let report_after = forensics!(watch, { work(&mut aead, of) });

        report_after.summary_against(&report_before, &format!("{what}, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived {what} of {of} bytes: {report_after}"
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

/// The sweep finds the secret when the secret is plainly there.
///
/// A test of its own, so the copy it plants is in nobody else's memory.
#[test]
fn test_the_sweep_finds_the_secret_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = vec![0_u8; SECRET.len()];

    giving(&mut held);
    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the secret, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where a copy lives, so every absence this file \
         reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box(held));

    Ok(())
}

// ============================================================================
// Aead::encrypt
// ============================================================================

/// In place, so the plaintext is gone from the buffer when it returns.
#[test]
fn test_encrypting_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("encrypted", |aead, of| {
        let key = vec![0x5A_u8; aead.key_size()];
        let nonce = aead.generate_nonce()?;
        let mut tag = vec![0_u8; aead.tag_size()];
        let mut data = vec![0_u8; of];

        giving(&mut data);

        aead.encrypt(&key, &nonce, &[], &mut data, &mut tag)?;

        data.fast_zeroize();

        drop(core::hint::black_box((data, tag, nonce, key)));

        Ok(())
    })
}

// ============================================================================
// Aead::decrypt
// ============================================================================

/// And the trip back, which is where the plaintext reappears.
#[test]
fn test_decrypting_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("decrypted", |aead, of| {
        let key = vec![0x5A_u8; aead.key_size()];
        let nonce = aead.generate_nonce()?;
        let mut tag = vec![0_u8; aead.tag_size()];
        let mut data = vec![0_u8; of];

        giving(&mut data);

        aead.encrypt(&key, &nonce, &[], &mut data, &mut tag)?;
        aead.decrypt(&key, &nonce, &[], &mut data, &tag)?;

        data.fast_zeroize();

        drop(core::hint::black_box((data, tag, nonce, key)));

        Ok(())
    })
}
