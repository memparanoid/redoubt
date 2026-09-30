// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a `RedoubtSecret` leave behind, into an empty one
//! and over one that already holds a secret.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, is_found, leaves_nothing};
use redoubt_secret::RedoubtSecret;
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::EncodeError;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::{SECRET, backwards};

/// A second secret, sharing no run with `SECRET`, for the value a decode puts
/// where that one was.
const OTHER: [u8; 32] = [
    0x27, 0xC8, 0x6B, 0x15, 0xE0, 0x93, 0x4D, 0xFA, 0x3E, 0x81, 0xD6, 0x09, 0xB2, 0x5F, 0x74, 0xAB,
    0x10, 0xE9, 0x36, 0x8C, 0x57, 0xF2, 0x0B, 0xC4, 0x69, 0xAD, 0x22, 0x9B, 0x40, 0xDD, 0x78, 0x05,
];

fn holding(from: &[u8; 32]) -> RedoubtSecret<[u8; 32]> {
    let mut source = [0_u8; 32];

    // SAFETY: both are thirty-two bytes, and a constant and a local are
    // different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(from.as_ptr(), source.as_mut_ptr(), from.len()) };

    RedoubtSecret::from(&mut source)
}

fn wire(from: &[u8; 32]) -> Result<Vec<u8>, AnyError> {
    let mut held = holding(from);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// BytesRequired for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds lengths."]
fn test_sizing_a_secret_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Encode for RedoubtSecret
// ============================================================================

#[redoubt_forensics::test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = holding(&SECRET);

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let buffer = Box::leak(Box::new(RedoubtCodecBuffer::with_capacity(
            held.encode_bytes_required()?,
        )));

        capture(|| held.encode_into(buffer))?;

        // What encode was given, emptied: what is found is what it wrote.
        held.fast_zeroize();
    });

    is_found(
        &watch.snapshot()?,
        "a buffer a secret was encoded into, and kept",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_encoding_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = holding(&SECRET);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret encoded");

    Ok(())
}

#[redoubt_forensics::test]
fn test_encoding_a_secret_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = holding(&SECRET);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()? / 2);

        let refused = capture(|| held.encode_into(&mut buffer));

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((held, buffer));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret encoded into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// Decode for RedoubtSecret
// ============================================================================

#[redoubt_forensics::test]
fn test_what_decoding_wrote_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut wire = wire(&SECRET)?;

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let back = Box::leak(Box::new(RedoubtSecret::<[u8; 32]>::default()));

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // What decode was given, emptied: what is found is what it wrote.
        wire.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a secret decoded into, and kept");

    Ok(())
}

#[redoubt_forensics::test]
fn test_decoding_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&SECRET)?;

    forensics!({
        let mut back = RedoubtSecret::<[u8; 32]>::default();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(back);

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret decoded");

    Ok(())
}

/// The value the secret held before is what is watched for, and the secret is
/// kept holding the one decoded: nothing of the old may be left anywhere.
#[redoubt_forensics::test]
fn test_decoding_over_a_secret_that_holds_one_leaves_nothing_of_the_old() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&OTHER)?;
    let mut back = holding(&SECRET);

    forensics!({
        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret decoded over one it held",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_decoding_a_secret_from_a_wire_cut_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&SECRET)?;
    let half = wire.len() / 2;

    forensics!({
        let mut back = RedoubtSecret::<[u8; 32]>::default();

        let refused = capture(|| back.decode_from(&mut &mut wire[..half]));

        assert!(refused.is_err(), "a wire cut short was not refused");

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The half decode was never handed is the test's to empty.
        wire[half..].fast_zeroize();

        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret decoded from a wire cut short",
    );

    Ok(())
}
