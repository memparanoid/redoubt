// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What decoding an `Option` leaves behind.
//!
//! Over `[u8; 32]`: inline and as wide as the secret, so a move of the value is
//! a copy of all of it.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

type Held = Option<[u8; 32]>;

fn some() -> Box<Held> {
    let mut held = Box::new(Some([0_u8; 32]));

    if let Some(inner) = held.as_mut() {
        giving(inner);
    }

    held
}

fn wire() -> Result<Vec<u8>, AnyError> {
    let mut held = some();
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
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
