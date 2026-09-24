// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What decoding a `String` leaves behind, into an empty one and over one that
//! already holds a secret.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::{TEXT, text_backwards};
use crate::tests::forensics::support::{is_found, leaves_nothing};

fn held(of: usize) -> String {
    let mut held = String::with_capacity(of);

    // SAFETY: every byte written below is ASCII, so what is left spells UTF-8.
    let bytes = unsafe { held.as_mut_vec() };

    bytes.resize(of, 0);

    for one in bytes.chunks_mut(TEXT.len()) {
        // SAFETY: `one` is at most as long as the text, and a constant and a
        // heap block are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(TEXT.as_ptr(), one.as_mut_ptr(), one.len()) };
    }

    held
}

fn wire(of: usize) -> Result<Vec<u8>, AnyError> {
    let mut held = held(of);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// String::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_string_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&text_backwards())?;

    forensics!({
        let mut back = String::new();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a string decoded, and kept");

    Ok(())
}

#[test]
fn test_decoding_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut back = String::new();

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
fn test_decoding_over_a_string_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut wire = wire(64)?;
    let mut back = held(32);
    let mut watch = Forensics::watching(&text_backwards())?;

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
        "encoded, and a string holding a secret",
        &watch.snapshot()?,
        "decoding over it",
    );

    Ok(())
}
