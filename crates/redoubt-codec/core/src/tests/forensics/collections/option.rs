// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding an `Option` leave behind.
//!
//! Over `[u8; 32]`: inline and as wide as the secret, so a move of the value is
//! a copy of all of it.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::option::{cleanup_decode_error, cleanup_encode_error};
use crate::error::{DecodeError, EncodeError};
use crate::traits::{BytesRequired, Decode, Encode, TryDecode, TryEncode};
use crate::types::Len;

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{
    a_buffer_holding, giving, is_found, leaves_nothing, secret_bytes,
};

type Held = Option<[u8; 32]>;

fn some() -> Box<Held> {
    let mut held = Box::new(Some([0_u8; 32]));

    if let Some(inner) = held.as_mut() {
        giving(inner);
    }

    held
}

fn wire_of(mut held: Box<Held>) -> Result<Vec<u8>, AnyError> {
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

fn wire() -> Result<Vec<u8>, AnyError> {
    wire_of(some())
}

/// A wire of `Some` whose header says neither `None` nor `Some`.
fn wire_of_neither() -> Result<Vec<u8>, AnyError> {
    let mut wire = wire()?;
    let neither: Len = 2;

    wire[..size_of::<Len>()].copy_from_slice(&neither.to_ne_bytes());

    Ok(wire)
}

// ============================================================================
// cleanup_encode_error
// ============================================================================

#[test]
fn test_cleaning_up_a_refused_encode_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = some();
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

    let mut held = some();
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
// Option::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_an_option_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Option::try_encode_into
// ============================================================================

#[test]
fn test_what_trying_to_encode_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = some();
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

    let mut held = some();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.try_encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The option is emptied here: trying leaves that to `encode_into`.
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
// Option::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = some();
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

    let mut held = some();

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

    let mut held = some();

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
// Option::try_decode_from
// ============================================================================

#[test]
fn test_what_trying_to_decode_some_wrote_is_found_while_the_option_holds_it() -> Result<(), AnyError>
{
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back: Box<Held> = Box::new(None);

        capture(|| back.try_decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "an option decoded, and kept");

    Ok(())
}

#[test]
fn test_trying_to_decode_some_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire()?;

    forensics!({
        let mut back: Box<Held> = Box::new(None);

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
        "trying to decode some",
    );

    Ok(())
}

// ============================================================================
// Option::decode_from
// ============================================================================

#[test]
fn test_what_decoding_some_wrote_is_found_while_the_option_holds_it() -> Result<(), AnyError> {
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back: Box<Held> = Box::new(None);

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "an option decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_some_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire()?;

    forensics!({
        let mut back: Box<Held> = Box::new(None);

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
        "decoding some",
    );

    Ok(())
}

#[test]
fn test_decoding_none_over_an_option_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_of(Box::new(None))?;
    let mut back = some();

    forensics!({
        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: what `Some` held is the operation's to
        // empty when it decodes `None` over it.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "decoding none over it",
    );

    Ok(())
}

#[test]
fn test_decoding_a_wire_that_says_neither_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_of_neither()?;

    forensics!({
        let mut back: Box<Held> = Box::new(None);

        let refused = capture(|| back.decode_from(&mut wire.as_mut_slice()));

        assert!(
            matches!(refused, Err(DecodeError::PreconditionViolated)),
            "a wire that says neither was not refused: {refused:?}"
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
        "decoding a wire that says neither",
    );

    Ok(())
}
