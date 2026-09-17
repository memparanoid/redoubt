// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a secret leave behind.
//!
//! # Why here, and why a sweep over sizes
//!
//! A cipherbox holding thirty-two bytes leaves nothing, and the same box
//! holding thirty-two kilobytes leaves the secret in plain sight. Between the
//! two there is one difference: how much every buffer on the way into the
//! ciphertext has to carry. The copy has been measured at every size it has a
//! path for and leaves nothing; so have the containers. This is the layer
//! underneath the box and above them.
//!
//! Encoding and decoding are separate tests on purpose. One of them failing
//! and not the other is the answer; both failing is a different answer.
//!
//! # Everything is cleared before the photograph
//!
//! The value, the buffer it was encoded into, and the value it was decoded
//! back out to. What is left was left by the encoding or the decoding, and not
//! by anything the test is still holding.

// Every measurement in this file was taken with an instrument that could not
// see past a call made after the operation, so each absence it reports is
// worth less than it says. Kept unbuilt, and only until `elenchos.rs` covers
// what it covered.
#![cfg(any())]

use redoubt_alloc::RedoubtVec;
use redoubt_codec_core::{Decode, Encode, RedoubtCodecBuffer};
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

/// Every size worth asking about, from one copy of the secret up to the size
/// at which the cipherbox above started leaving it behind.
const SIZES: [usize; 8] = [32, 64, 128, 512, 1024, 4096, 16384, 32768];

/// Room for the encoding, and then some: a length prefix and whatever else the
/// format puts in front.
const SPARE: usize = 1024;

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

/// A vec of that many bytes of the secret, filled the clean way.
fn held(of: usize) -> RedoubtVec<u8> {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    let mut held = RedoubtVec::<u8>::new();

    held.replace_from_mut_slice(&mut source);

    held
}

/// Everything a caller must be able to say about what an operation left, at
/// every size.
fn leaves_nothing_at_any_size(
    what: &str,
    mut work: impl FnMut(usize) -> Result<(), AnyError>,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing encoded yet");

    for of in SIZES {
        let report_after = forensics!(watch, { work(of) });

        report_after.summary_against(&report_before, &format!("{what}, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived {what} of {of} bytes: {report_after}",
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

    let mut seen_by = vec![0_u8; SECRET.len()];

    giving(&mut seen_by);
    core::hint::black_box(&seen_by);

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

    drop(core::hint::black_box(seen_by));

    Ok(())
}

// ============================================================================
// Encode
// ============================================================================

/// Into a buffer, and everything cleared behind it.
#[test]
fn test_encoding_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("encoded", |of| {
        let mut value = held(of);
        let mut buffer = RedoubtCodecBuffer::with_capacity(of + SPARE);

        value.encode_into(&mut buffer)?;

        value.fast_zeroize();
        buffer.fast_zeroize();

        drop(core::hint::black_box(buffer));
        drop(core::hint::black_box(value));

        Ok(())
    })
}

// ============================================================================
// Decode
// ============================================================================

/// Out of a buffer that already holds it, and everything cleared behind it.
///
/// The encoding is done before the photograph and its own leavings are not
/// what this is asking about — the test above asks that. What is measured is
/// the trip back.
#[test]
fn test_decoding_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("decoded", |of| {
        let mut value = held(of);
        let mut buffer = RedoubtCodecBuffer::with_capacity(of + SPARE);

        value.encode_into(&mut buffer)?;
        value.fast_zeroize();

        let mut wire = buffer.as_mut_slice().to_vec();
        let mut reading = &mut wire[..];
        let mut back = RedoubtVec::<u8>::new();

        back.decode_from(&mut reading)?;

        back.fast_zeroize();
        buffer.fast_zeroize();
        wire.fast_zeroize();

        drop(core::hint::black_box((back, buffer, wire, value)));

        Ok(())
    })
}
