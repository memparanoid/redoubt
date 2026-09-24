// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What decoding a `Vec` leaves behind, into an empty one and over one that
//! already holds a secret.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

fn held(of: usize) -> Vec<u8> {
    let mut held = vec![0_u8; of];

    giving(&mut held);

    held
}

fn wire(of: usize) -> Result<Vec<u8>, AnyError> {
    let mut held = held(of);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// Vec::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_vec_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back: Vec<u8> = Vec::new();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a vec decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut back: Vec<u8> = Vec::new();

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
        "encoded, nothing decoded",
        &watch.snapshot()?,
        "decoding",
    );

    Ok(())
}

#[test]
fn test_decoding_over_a_vec_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut back = held(32);
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

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
        "encoded, and a vec holding a secret",
        &watch.snapshot()?,
        "decoding over it",
    );

    Ok(())
}

#[test]
fn test_decoding_less_over_a_vec_that_holds_more_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire(2048)?;
    let mut back = held(4096);
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

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
        "encoded, and a vec holding more of the secret",
        &watch.snapshot()?,
        "decoding less over it",
    );

    Ok(())
}
