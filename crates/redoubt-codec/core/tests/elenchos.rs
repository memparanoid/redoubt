// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a secret leave behind.
//!
//! # Why here, and why every size
//!
//! A cipherbox holding thirty-two bytes leaves nothing, and the same box
//! holding thirty-two kilobytes leaves the secret in plain sight. Between the
//! two there is one difference: how much every buffer on the way into the
//! ciphertext has to carry. The copy has been measured at every size it has a
//! path for and leaves nothing; so have the containers. This is the layer
//! underneath the box and above them.
//!
//! It is also the layer the rest of the workspace rests on. `Encode` for a vec
//! empties what it read as it reads it, and every absence a cipherbox reports
//! is that one line holding.
//!
//! Encoding and decoding are separate sections on purpose. One of them failing
//! and not the other is the answer; both failing is a different answer.
//!
//! # Two tests for every claim
//!
//! Each section opens with the same operation run against something that is
//! never cleared, and that one has to be **found**. An absence is worth
//! exactly as much as the presence beside it: a sweep that reaches nowhere
//! reports a clean process, and so does an encoding that left nothing.
//!
//! # One size per test
//!
//! The sweep reads the whole process, so a size that leaks leaves the secret
//! in memory and every size measured after it in the same process finds that
//! copy and is blamed for it. Under `nextest` each test is a process of its
//! own, so the size that failed is the name of the test that failed.

#![cfg(target_os = "linux")]

use redoubt_alloc::RedoubtVec;
use redoubt_codec_core::{Decode, Encode, RedoubtCodecBuffer};
use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, elenchos};
use redoubt_zero::FastZeroizable;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Room for the encoding, and then some: a length prefix and whatever else the
/// format puts in front.
const SPARE: usize = 1024;

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
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

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
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
/// The whole secret is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing encoded yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
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
// Encode
// ============================================================================

/// The value the encoding is handed is found while it is still holding it.
///
/// It has to be held from before the call: `encode_into` empties what it read
/// as it reads it, so a value kept afterwards is a value that is already
/// empty. That is the line every absence in this workspace rests on, and this
/// is the test that says the sweep can see whether it ran.
#[test]
fn test_a_value_is_found_while_it_holds_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    elenchos!({
        let value = held(32);

        capture!();

        core::mem::forget(value);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a value built, and kept");

    Ok(())
}

/// The buffer is found while it holds the encoding.
///
/// What goes into the buffer is the secret itself with a header in front of
/// it — the encoding is not a cipher, and nothing about it hides anything. So
/// the same needle finds it there, which is what says the absence below is
/// about the buffer having been emptied rather than about the sweep missing
/// it.
#[test]
fn test_a_buffer_is_found_while_it_holds_the_encoding() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    elenchos!({
        let mut value = held(32);
        let mut buffer = RedoubtCodecBuffer::with_capacity(32 + SPARE);

        value.encode_into(&mut buffer)?;

        capture!();

        core::mem::forget(buffer);

        drop(value);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a buffer holding the encoding");

    Ok(())
}

/// Into a buffer, and everything cleared behind it.
macro_rules! encoded {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            elenchos!({
                let mut value = held($of);
                let mut buffer = RedoubtCodecBuffer::with_capacity($of + SPARE);

                value.encode_into(&mut buffer)?;

                capture!();

                value.fast_zeroize();
                buffer.fast_zeroize();

                drop(buffer);
                drop(value);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("encoded {} bytes", $of),
            );

            Ok(())
        }
    };
}

encoded!(test_encoding_32_bytes_leaves_nothing, 32);
encoded!(test_encoding_64_bytes_leaves_nothing, 64);
encoded!(test_encoding_128_bytes_leaves_nothing, 128);
encoded!(test_encoding_512_bytes_leaves_nothing, 512);
encoded!(test_encoding_1024_bytes_leaves_nothing, 1024);
encoded!(test_encoding_4096_bytes_leaves_nothing, 4096);
encoded!(test_encoding_16384_bytes_leaves_nothing, 16384);
encoded!(test_encoding_32768_bytes_leaves_nothing, 32768);

// ============================================================================
// Decode
// ============================================================================

/// What came back out is found while it is still holding it.
#[test]
fn test_a_decoded_value_is_found_while_it_holds_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    elenchos!({
        let mut value = held(32);
        let mut buffer = RedoubtCodecBuffer::with_capacity(32 + SPARE);

        value.encode_into(&mut buffer)?;

        let mut wire = buffer.as_mut_slice().to_vec();
        let mut reading = &mut wire[..];
        let mut back = RedoubtVec::<u8>::new();

        back.decode_from(&mut reading)?;

        capture!();

        core::mem::forget(back);

        buffer.fast_zeroize();
        wire.fast_zeroize();

        drop((buffer, wire, value));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a decoded value, kept");

    Ok(())
}

/// Out of a buffer that already holds it, and everything cleared behind it.
///
/// The encoding happens inside the block as well, and its own leavings are not
/// what this is asking about — the section above asks that. What is measured
/// is the trip back, which is why the capture is the instruction after it.
macro_rules! decoded {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            elenchos!({
                let mut value = held($of);
                let mut buffer = RedoubtCodecBuffer::with_capacity($of + SPARE);

                value.encode_into(&mut buffer)?;
                value.fast_zeroize();

                let mut wire = buffer.as_mut_slice().to_vec();
                let mut reading = &mut wire[..];
                let mut back = RedoubtVec::<u8>::new();

                back.decode_from(&mut reading)?;

                capture!();

                back.fast_zeroize();
                buffer.fast_zeroize();
                wire.fast_zeroize();

                drop((back, buffer, wire, value));
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("decoded {} bytes", $of),
            );

            Ok(())
        }
    };
}

decoded!(test_decoding_32_bytes_leaves_nothing, 32);
decoded!(test_decoding_64_bytes_leaves_nothing, 64);
decoded!(test_decoding_128_bytes_leaves_nothing, 128);
decoded!(test_decoding_512_bytes_leaves_nothing, 512);
decoded!(test_decoding_1024_bytes_leaves_nothing, 1024);
decoded!(test_decoding_4096_bytes_leaves_nothing, 4096);
decoded!(test_decoding_16384_bytes_leaves_nothing, 16384);
decoded!(test_decoding_32768_bytes_leaves_nothing, 32768);
