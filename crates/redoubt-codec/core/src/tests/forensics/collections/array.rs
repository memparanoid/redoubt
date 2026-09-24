// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding an array leave behind.
//!
//! Over `[u8; 32]`: inline and as wide as the secret, so a copy of the array
//! is a copy of all of it.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::array::{cleanup_decode_error, cleanup_encode_error};
use crate::error::{DecodeError, EncodeError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, TryDecode, TryEncode,
};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{
    a_buffer_holding, giving, is_found, leaves_nothing, secret_bytes,
};

type Held = [u8; 32];

fn hold() -> Box<Held> {
    let mut held = Box::new([0_u8; 32]);

    giving(&mut *held);

    held
}

fn two() -> Box<[Held; 2]> {
    let mut two = Box::new([[0_u8; 32]; 2]);

    for one in two.iter_mut() {
        giving(one);
    }

    two
}

fn wire() -> Result<Vec<u8>, AnyError> {
    let mut held = hold();
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

fn two_wire() -> Result<Vec<u8>, AnyError> {
    let mut two = two();
    let mut buffer = RedoubtCodecBuffer::with_capacity(2 * two[0].encode_bytes_required()?);

    Held::encode_slice_into(&mut *two, &mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// cleanup_encode_error
// ============================================================================

#[test]
fn test_cleaning_up_a_refused_encode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();
    let mut buffer = a_buffer_holding()?;

    forensics!({
        capture(|| cleanup_encode_error(&mut held, &mut buffer));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((held, buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "cleaning up a refused encode",
    );

    Ok(())
}

// ============================================================================
// cleanup_decode_error
// ============================================================================

#[test]
fn test_cleaning_up_a_refused_decode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();
    let mut wire = secret_bytes(64);

    forensics!({
        capture(|| cleanup_decode_error(&mut held, &mut wire.as_mut_slice()));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((held, wire));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "cleaning up a refused decode",
    );

    Ok(())
}

// ============================================================================
// [T; N]::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_an_array_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// [T; N]::try_encode_into
// ============================================================================

#[test]
fn test_what_trying_to_encode_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = hold();
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.try_encode_into(&mut buffer))?;

        // Emptied, so what is found can only be what was written.
        held.fast_zeroize();

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_trying_to_encode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.try_encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The array is emptied here: trying leaves that to `encode_into`.
        held.fast_zeroize();
        buffer.fast_zeroize();
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "trying to encode",
    );

    Ok(())
}

// ============================================================================
// [T; N]::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = hold();
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.encode_into(&mut buffer))?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(held);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding",
    );

    Ok(())
}

#[test]
fn test_encoding_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()? - 1);

        let refused = capture(|| held.encode_into(&mut buffer));

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((held, buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// [T; N]::encode_slice_into
// ============================================================================

#[test]
fn test_what_encoding_a_slice_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut two = two();
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(2 * two[0].encode_bytes_required()?);

        capture(|| Held::encode_slice_into(&mut *two, &mut buffer))?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut two = two();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(2 * two[0].encode_bytes_required()?);

        capture(|| Held::encode_slice_into(&mut *two, &mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget(two);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding a slice",
    );

    Ok(())
}

// ============================================================================
// [T; N]::try_decode_from
// ============================================================================

#[test]
fn test_what_trying_to_decode_wrote_is_found_while_the_array_holds_it() -> Result<(), AnyError> {
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new([0_u8; 32]);

        capture(|| back.try_decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "an array decoded, and kept");

    Ok(())
}

#[test]
fn test_trying_to_decode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire()?;

    forensics!({
        let mut back = Box::new([0_u8; 32]);

        capture(|| back.try_decode_from(&mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        back.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "trying to decode",
    );

    Ok(())
}

// ============================================================================
// [T; N]::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_array_holds_it() -> Result<(), AnyError> {
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new([0_u8; 32]);

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "an array decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire()?;

    forensics!({
        let mut back = Box::new([0_u8; 32]);

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        back.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding",
    );

    Ok(())
}

#[test]
fn test_decoding_into_an_array_of_another_width_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire()?;

    forensics!({
        let mut back = Box::new([0_u8; 16]);

        let refused = capture(|| back.decode_from(&mut wire.as_mut_slice()));

        assert!(
            matches!(refused, Err(DecodeError::PreconditionViolated)),
            "an array of another width was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding into an array of another width",
    );

    Ok(())
}

// ============================================================================
// [T; N]::decode_slice_from
// ============================================================================

#[test]
fn test_what_decoding_a_slice_wrote_is_found_while_the_arrays_hold_it() -> Result<(), AnyError> {
    let mut wire = two_wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new([[0_u8; 32]; 2]);

        capture(|| Held::decode_slice_from(&mut *back, &mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "arrays decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = two_wire()?;

    forensics!({
        let mut back = Box::new([[0_u8; 32]; 2]);

        capture(|| Held::decode_slice_from(&mut *back, &mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        back.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding a slice",
    );

    Ok(())
}

// ============================================================================
// [T; N]::prealloc
// ============================================================================

#[test]
#[ignore = "Reads no secret: it does nothing."]
fn test_preallocating_an_array_leaves_nothing() {
    // Intentionally empty.
}
