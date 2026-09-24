// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding the fields of a struct leave behind, one after
//! the other, and when one of them fails.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::helpers::{
    decode_fields, encode_fields, to_decode_zeroize_dyn_mut, to_encode_zeroize_dyn_mut,
};
use crate::error::{DecodeError, EncodeError};
use crate::traits::{BytesRequired, Decode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{is_found, leaves_nothing, secret_bytes};

/// A field that refuses to decode and leaves the buffer as it was: the codec's
/// own types empty it when they fail, and the wipe after them would go
/// unmeasured.
#[derive(Default)]
struct Refusing;

impl Decode for Refusing {
    fn decode_from(&mut self, _: &mut &mut [u8]) -> Result<(), DecodeError> {
        Err(DecodeError::IntentionalDecodeError)
    }
}

impl FastZeroizable for Refusing {
    fn fast_zeroize(&mut self) {}
}

fn two_wire() -> Result<Vec<u8>, AnyError> {
    let (mut first, mut second) = (secret_bytes(32), secret_bytes(32));
    let mut buffer = RedoubtCodecBuffer::with_capacity(
        first.encode_bytes_required()? + second.encode_bytes_required()?,
    );

    encode_fields(
        [
            to_encode_zeroize_dyn_mut(&mut first),
            to_encode_zeroize_dyn_mut(&mut second),
        ]
        .into_iter(),
        &mut buffer,
    )?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// header_size
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a width."]
fn test_sizing_a_header_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// write_header
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes two lengths."]
fn test_writing_a_header_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// process_header
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads two lengths."]
fn test_processing_a_header_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_bytes_required_dyn_ref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back the reference it is given."]
fn test_casting_to_a_bytes_required_dyn_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_encode_dyn_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back the reference it is given."]
fn test_casting_to_an_encode_dyn_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_decode_dyn_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back the reference it is given."]
fn test_casting_to_a_decode_dyn_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_encode_zeroize_dyn_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back the reference it is given."]
fn test_casting_to_an_encode_zeroize_dyn_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_decode_zeroize_dyn_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back the reference it is given."]
fn test_casting_to_a_decode_zeroize_dyn_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// bytes_required_sum
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds lengths."]
fn test_summing_bytes_required_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// encode_fields
// ============================================================================

#[test]
fn test_what_encoding_fields_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let (mut first, mut second) = (secret_bytes(32), secret_bytes(32));
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(
            first.encode_bytes_required()? + second.encode_bytes_required()?,
        );

        capture(|| {
            encode_fields(
                [
                    to_encode_zeroize_dyn_mut(&mut first),
                    to_encode_zeroize_dyn_mut(&mut second),
                ]
                .into_iter(),
                &mut buffer,
            )
        })?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_fields_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let (mut first, mut second) = (secret_bytes(32), secret_bytes(32));

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(
            first.encode_bytes_required()? + second.encode_bytes_required()?,
        );

        capture(|| {
            encode_fields(
                [
                    to_encode_zeroize_dyn_mut(&mut first),
                    to_encode_zeroize_dyn_mut(&mut second),
                ]
                .into_iter(),
                &mut buffer,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding fields",
    );

    Ok(())
}

/// Room for the first field and not the second, so the third is never reached:
/// the encode that failed and the one that never ran are both emptied by the
/// loop.
#[test]
fn test_encoding_fields_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let (mut first, mut second, mut third) = (secret_bytes(32), secret_bytes(32), secret_bytes(32));

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(first.encode_bytes_required()?);

        let refused = capture(|| {
            encode_fields(
                [
                    to_encode_zeroize_dyn_mut(&mut first),
                    to_encode_zeroize_dyn_mut(&mut second),
                    to_encode_zeroize_dyn_mut(&mut third),
                ]
                .into_iter(),
                &mut buffer,
            )
        });

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second, third, buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding fields into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// decode_fields
// ============================================================================

#[test]
fn test_what_decoding_fields_wrote_is_found_while_the_fields_hold_it() -> Result<(), AnyError> {
    let mut wire = two_wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let (mut first, mut second) = (Vec::<u8>::new(), Vec::<u8>::new());

        capture(|| {
            decode_fields(
                [
                    to_decode_zeroize_dyn_mut(&mut first),
                    to_decode_zeroize_dyn_mut(&mut second),
                ]
                .into_iter(),
                &mut wire.as_mut_slice(),
            )
        })?;

        core::mem::forget((first, second));
    });

    is_found(&watch.snapshot()?, "fields decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_fields_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = two_wire()?;

    forensics!({
        let (mut first, mut second) = (Vec::<u8>::new(), Vec::<u8>::new());

        capture(|| {
            decode_fields(
                [
                    to_decode_zeroize_dyn_mut(&mut first),
                    to_decode_zeroize_dyn_mut(&mut second),
                ]
                .into_iter(),
                &mut wire.as_mut_slice(),
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        first.fast_zeroize();
        second.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding fields",
    );

    Ok(())
}

/// The first field decodes and the second refuses without touching the
/// buffer, so what empties the first field and what is left of the wire is the
/// loop.
#[test]
fn test_decoding_fields_refused_by_one_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = two_wire()?;

    forensics!({
        let (mut first, mut second) = (Vec::<u8>::new(), Refusing);

        let refused = capture(|| {
            decode_fields(
                [
                    to_decode_zeroize_dyn_mut(&mut first),
                    to_decode_zeroize_dyn_mut(&mut second),
                ]
                .into_iter(),
                &mut wire.as_mut_slice(),
            )
        });

        assert!(
            matches!(refused, Err(DecodeError::IntentionalDecodeError)),
            "the second field decoded: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, wire));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding fields refused by one",
    );

    Ok(())
}
