// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a primitive leave behind.
//!
//! Over `u128`, the widest: one value is sixteen bytes of the secret, and a
//! slice of two is all of it.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError};
use crate::traits::{Decode, DecodeSlice, Encode, EncodeSlice, TryDecode, TryEncode};

use crate::tests::forensics::support::needles::{backwards, half_backwards};
use crate::tests::forensics::support::{a_u128, giving, is_found, leaves_nothing, two_u128};

fn wire(of: usize) -> Vec<u8> {
    let mut wire = vec![0_u8; of];

    giving(&mut wire);

    wire
}

// ============================================================================
// u128::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers the width of the type."]
fn test_sizing_a_primitive_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// u128::try_encode_into
// ============================================================================

#[test]
fn test_what_trying_to_encode_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut value = a_u128();
    let mut watch = Forensics::watching(&half_backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| value.try_encode_into(&mut buffer))?;

        // Emptied, so what is found can only be what was written.
        value.fast_zeroize();

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_trying_to_encode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut value = a_u128();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| value.try_encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The value is emptied here: trying leaves that to `encode_into`.
        value.fast_zeroize();
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
// u128::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut value = a_u128();
    let mut watch = Forensics::watching(&half_backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| value.encode_into(&mut buffer))?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut value = a_u128();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| value.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(value);
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
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut value = a_u128();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(8);

        let refused = capture(|| value.encode_into(&mut buffer));

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((value, buffer));
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
// u128::encode_slice_into
// ============================================================================

#[test]
fn test_what_encoding_a_slice_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut values = two_u128();
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(32);

        capture(|| u128::encode_slice_into(&mut *values, &mut buffer))?;

        // Emptied, so what is found can only be what was written.
        values.fast_zeroize();

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut values = two_u128();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(32);

        capture(|| u128::encode_slice_into(&mut *values, &mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The slice is emptied here: encoding a slice leaves that to the
        // collection that holds it.
        values.fast_zeroize();
        buffer.fast_zeroize();
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
// u128::try_decode_from
// ============================================================================

#[test]
fn test_what_trying_to_decode_wrote_is_found_while_the_value_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(16);
    let mut watch = Forensics::watching(&half_backwards())?;

    forensics!({
        let mut back = Box::new(0_u128);

        capture(|| back.try_decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a value decoded, and kept");

    Ok(())
}

#[test]
fn test_trying_to_decode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(16);

    forensics!({
        let mut back = Box::new(0_u128);

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
// u128::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_value_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(16);
    let mut watch = Forensics::watching(&half_backwards())?;

    forensics!({
        let mut back = Box::new(0_u128);

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a value decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(16);

    forensics!({
        let mut back = Box::new(0_u128);

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
fn test_decoding_out_of_a_wire_too_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(15);

    forensics!({
        let mut back = Box::new(0_u128);

        let refused = capture(|| back.decode_from(&mut wire.as_mut_slice()));

        assert!(
            matches!(refused, Err(DecodeError::DecodeBufferError(_))),
            "a wire too short was not refused: {refused:?}"
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
        "decoding out of a wire too short",
    );

    Ok(())
}

// ============================================================================
// u128::decode_slice_from
// ============================================================================

#[test]
fn test_what_decoding_a_slice_wrote_is_found_while_the_slice_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(32);
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new([0_u128; 2]);

        capture(|| u128::decode_slice_from(&mut *back, &mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a slice decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(32);

    forensics!({
        let mut back = Box::new([0_u128; 2]);

        capture(|| u128::decode_slice_from(&mut *back, &mut wire.as_mut_slice()))?;

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
// u128::prealloc
// ============================================================================

#[test]
#[ignore = "Reads no secret: it does nothing."]
fn test_preallocating_a_primitive_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// bool
// ============================================================================

#[test]
#[ignore = "Unmeasurable: a bool is one byte, below any run the sweep can tell from chance."]
fn test_encoding_and_decoding_a_bool_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// decoded_bool
// ============================================================================

#[test]
#[ignore = "Unmeasurable: a bool is one byte, below any run the sweep can tell from chance."]
fn test_reading_a_byte_as_a_bool_leaves_nothing() {
    // Intentionally empty.
}
