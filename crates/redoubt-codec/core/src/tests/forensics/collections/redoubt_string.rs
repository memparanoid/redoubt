// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a `RedoubtString` leave behind, into an empty one
//! and over one that already holds a secret.

use redoubt_alloc::RedoubtString;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::text_backwards;
use crate::tests::forensics::support::{is_found, leaves_nothing, text};

fn hold(of: usize) -> RedoubtString {
    let mut source = text(of);
    let mut held = RedoubtString::new();

    held.replace_from_mut_string(&mut source);

    held
}

fn wire(of: usize) -> Result<Vec<u8>, AnyError> {
    let mut held = hold(of);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// RedoubtString::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut held = hold(32);
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

    let mut held = hold(32);

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

// ============================================================================
// RedoubtString::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_redoubt_string_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&text_backwards())?;

    forensics!({
        let mut back = RedoubtString::new();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a redoubt string decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(64)?;

    forensics!({
        let mut back = RedoubtString::new();

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
fn test_decoding_less_over_a_redoubt_string_that_holds_more_leaves_nothing() -> Result<(), AnyError>
{
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(2048)?;
    let mut back = hold(4096);

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
        "decoding less over it",
    );

    Ok(())
}
