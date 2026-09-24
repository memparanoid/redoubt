// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding through a `Box` leave behind.
//!
//! Over `[u8; 32]`: inline and as wide as the secret, so a copy of the value
//! on the way through the box is a copy of all of it.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

fn boxed() -> Box<[u8; 32]> {
    let mut boxed = Box::new([0_u8; 32]);

    giving(&mut *boxed);

    boxed
}

fn wire() -> Result<Vec<u8>, AnyError> {
    let mut boxed = boxed();
    let mut buffer = RedoubtCodecBuffer::with_capacity(boxed.encode_bytes_required()?);

    boxed.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// Box::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_a_box_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Box::encode_into
// ============================================================================

#[test]
fn test_what_encoding_a_box_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut boxed = boxed();
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(boxed.encode_bytes_required()?);

        capture(|| boxed.encode_into(&mut buffer))?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_a_box_leaves_nothing() -> Result<(), AnyError> {
    let mut boxed = boxed();
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(boxed.encode_bytes_required()?);

        capture(|| boxed.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(boxed);
    });

    leaves_nothing(
        &report_before,
        "a box holding the secret",
        &watch.snapshot()?,
        "encoding a box",
    );

    Ok(())
}

// ============================================================================
// Box::decode_from
// ============================================================================

#[test]
fn test_what_decoding_a_box_wrote_is_found_while_the_box_holds_it() -> Result<(), AnyError> {
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new([0_u8; 32]);

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a box decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_a_box_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire()?;
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

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
        "a wire holding the secret",
        &watch.snapshot()?,
        "decoding a box",
    );

    Ok(())
}
