// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a `String` leave behind, into an empty one and
//! over one that already holds a secret.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::string::{cleanup_decode_error, cleanup_encode_error};
use crate::error::{DecodeError, EncodeError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode, TryEncode,
};

use crate::tests::forensics::support::needles::{backwards, text_backwards};
use crate::tests::forensics::support::{is_found, leaves_nothing, secret_bytes, text};

type Held = String;

fn two() -> Box<[Held; 2]> {
    Box::new([text(32), text(32)])
}

fn a_buffer_holding_text() -> Result<RedoubtCodecBuffer, AnyError> {
    let mut source = text(32);
    let mut buffer = RedoubtCodecBuffer::with_capacity(32);

    // SAFETY: nothing is written back through these bytes.
    buffer.write_slice(unsafe { source.as_bytes_mut() })?;

    source.fast_zeroize();

    Ok(buffer)
}

fn wire(of: usize) -> Result<Vec<u8>, AnyError> {
    let mut held = text(of);
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

/// A wire laid out as a `String`'s, carrying bytes that are not UTF-8.
fn wire_not_utf8() -> Result<Vec<u8>, AnyError> {
    let mut bytes = secret_bytes(32);
    let mut buffer = RedoubtCodecBuffer::with_capacity(bytes.encode_bytes_required()?);

    bytes.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// cleanup_encode_error
// ============================================================================

#[test]
fn test_cleaning_up_a_refused_encode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = text(32);
    let mut buffer = a_buffer_holding_text()?;

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
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = text(32);
    let mut wire = wire(64)?;

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
// string_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds a length to the header's."]
fn test_sizing_a_string_by_its_length_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// String::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_a_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// String::try_encode_into
// ============================================================================

#[test]
fn test_what_trying_to_encode_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = text(32);
    let mut watch = Forensics::watching(&text_backwards())?;

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
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = text(32);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.try_encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The string is emptied here: trying leaves that to `encode_into`.
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
// String::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = text(32);
    let mut watch = Forensics::watching(&text_backwards())?;

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
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = text(32);

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
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = text(32);

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
// String::encode_slice_into
// ============================================================================

#[test]
fn test_what_encoding_a_slice_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut two = two();
    let mut watch = Forensics::watching(&text_backwards())?;

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
    let mut watch = Forensics::watching(&text_backwards())?;

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
// String::try_decode_from
// ============================================================================

#[test]
fn test_what_trying_to_decode_wrote_is_found_while_the_string_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&text_backwards())?;

    forensics!({
        let mut back = Held::new();

        capture(|| back.try_decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a string decoded, and kept");

    Ok(())
}

#[test]
fn test_trying_to_decode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(64)?;

    forensics!({
        let mut back = Held::new();

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
// String::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_string_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&text_backwards())?;

    forensics!({
        let mut back = Held::new();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a string decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(64)?;

    forensics!({
        let mut back = Held::new();

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
fn test_decoding_over_a_string_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(64)?;
    let mut back = text(32);

    forensics!({
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
        "decoding over it",
    );

    Ok(())
}

#[test]
fn test_decoding_out_of_a_wire_cut_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(64)?;

    forensics!({
        let mut back = Held::new();
        let cut = wire.len() - 1;

        let refused = capture(|| back.decode_from(&mut &mut wire[..cut]));

        assert!(
            matches!(refused, Err(DecodeError::PreconditionViolated)),
            "a wire cut short was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying what is left of the wire is the
        // operation's, and the byte cut off is one byte, below any run.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding out of a wire cut short",
    );

    Ok(())
}

/// The bytes are in the string before they are found not to be UTF-8, so what
/// empties them is the cleanup of the refusal.
#[test]
fn test_decoding_bytes_that_are_not_utf8_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_not_utf8()?;

    forensics!({
        let mut back = Held::new();

        let refused = capture(|| back.decode_from(&mut wire.as_mut_slice()));

        assert!(
            matches!(refused, Err(DecodeError::PreconditionViolated)),
            "bytes that are not UTF-8 were not refused: {refused:?}"
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
        "decoding bytes that are not UTF-8",
    );

    Ok(())
}

// ============================================================================
// String::decode_slice_from
// ============================================================================

#[test]
fn test_what_decoding_a_slice_wrote_is_found_while_the_strings_hold_it() -> Result<(), AnyError> {
    let mut wire = two_wire()?;
    let mut watch = Forensics::watching(&text_backwards())?;

    forensics!({
        let mut back = Box::new([Held::new(), Held::new()]);

        capture(|| Held::decode_slice_from(&mut *back, &mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "strings decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = two_wire()?;

    forensics!({
        let mut back = Box::new([Held::new(), Held::new()]);

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
// String::prealloc
// ============================================================================

#[test]
fn test_preallocating_over_a_string_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut back = text(4096);

    forensics!({
        capture(|| back.prealloc(2048));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(back);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "preallocating over it",
    );

    Ok(())
}
