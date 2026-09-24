// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encoding and decoding a `RedoubtVec` leave behind, at every size the
//! copy has a path for.

use redoubt_alloc::RedoubtVec;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

fn held(of: usize) -> RedoubtVec<u8> {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    let mut held = RedoubtVec::<u8>::new();

    held.replace_from_mut_slice(&mut source);

    held
}

fn wire(of: usize) -> Result<Vec<u8>, AnyError> {
    let mut held = held(of);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// RedoubtVec::encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it counts bytes."]
fn test_sizing_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::encode_into
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut value = held(32);
        let mut buffer = RedoubtCodecBuffer::with_capacity(value.encode_bytes_required()?);

        capture(|| value.encode_into(&mut buffer))?;

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer holding the encoding");

    Ok(())
}

macro_rules! encoded {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            forensics!({
                let mut value = held($of);
                let mut buffer = RedoubtCodecBuffer::with_capacity(value.encode_bytes_required()?);

                capture(|| value.encode_into(&mut buffer))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                buffer.fast_zeroize();

                // Forgotten and not emptied: emptying it is the operation's.
                core::mem::forget(value);
            });

            leaves_nothing(
                &report_before,
                "nothing encoded yet",
                &watch.snapshot()?,
                &format!("encoded {} bytes", $of),
            );

            Ok(())
        }
    };
}

encoded!(test_encoding_32_bytes_leaves_nothing, 32);
encoded!(test_encoding_64_bytes_leaves_nothing, 64);
encoded!(test_encoding_128_bytes_leaves_nothing, 128);
encoded!(test_encoding_512_bytes_leaves_nothing, 512);
encoded!(test_encoding_1024_bytes_leaves_nothing, 1024);
encoded!(test_encoding_4096_bytes_leaves_nothing, 4096);
encoded!(test_encoding_16384_bytes_leaves_nothing, 16384);
encoded!(test_encoding_32768_bytes_leaves_nothing, 32768);

// ============================================================================
// RedoubtVec::decode_from
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_redoubt_vec_holds_it() -> Result<(), AnyError> {
    let mut wire = wire(32)?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut back = RedoubtVec::<u8>::new();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        core::mem::forget(back);
    });

    is_found(&watch.snapshot()?, "a redoubt vec decoded, and kept");

    Ok(())
}

macro_rules! decoded {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut wire = wire($of)?;
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            forensics!({
                let mut back = RedoubtVec::<u8>::new();

                capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                back.fast_zeroize();

                // Forgotten and not emptied: emptying it is the operation's.
                core::mem::forget(wire);
            });

            leaves_nothing(
                &report_before,
                "encoded, nothing decoded",
                &watch.snapshot()?,
                &format!("decoded {} bytes", $of),
            );

            Ok(())
        }
    };
}

decoded!(test_decoding_32_bytes_leaves_nothing, 32);
decoded!(test_decoding_64_bytes_leaves_nothing, 64);
decoded!(test_decoding_128_bytes_leaves_nothing, 128);
decoded!(test_decoding_512_bytes_leaves_nothing, 512);
decoded!(test_decoding_1024_bytes_leaves_nothing, 1024);
decoded!(test_decoding_4096_bytes_leaves_nothing, 4096);
decoded!(test_decoding_16384_bytes_leaves_nothing, 16384);
decoded!(test_decoding_32768_bytes_leaves_nothing, 32768);
