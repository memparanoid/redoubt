// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a `RedoubtOption` leave behind.
//!
//! Over `[u8; 32]`: inline and as wide as the secret, so a move of the value is
//! a copy of all of it.

use redoubt_alloc::RedoubtOption;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

type Held = RedoubtOption<[u8; 32]>;

fn some() -> Box<Held> {
    let mut source = [0_u8; 32];

    giving(&mut source);

    let mut held = Box::new(Held::default());

    held.replace(&mut source);

    held
}

fn wire_of(mut held: Box<Held>) -> Result<Vec<u8>, AnyError> {
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// RedoubtOption::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_a_redoubt_option_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::encode_into
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

// ============================================================================
// RedoubtOption::decode_from
// ============================================================================

#[test]
fn test_what_decoding_some_wrote_is_found_while_the_redoubt_option_holds_it() -> Result<(), AnyError>
{
    let mut wire = wire_of(some())?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = Box::new(Held::default());

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a redoubt option decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_some_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_of(some())?;

    forensics!({
        let mut back = Box::new(Held::default());

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
fn test_decoding_some_over_a_redoubt_option_that_holds_a_secret_leaves_nothing()
-> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_of(some())?;
    let mut back = some();

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
        "decoding some over it",
    );

    Ok(())
}

#[test]
fn test_decoding_none_over_a_redoubt_option_that_holds_a_secret_leaves_nothing()
-> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire_of(Box::default())?;
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
