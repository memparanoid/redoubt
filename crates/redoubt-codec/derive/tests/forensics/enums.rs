// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::{RedoubtArray, RedoubtString};
use redoubt_codec_core::{BytesRequired, Decode, DecodeError, Encode, RedoubtCodecBuffer};
use redoubt_codec_derive::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, capture, forensics, is_found, leaves_nothing};
use redoubt_secret::RedoubtSecret;
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::support::needles::backwards;
use crate::support::{a_text, an_array, secret};

#[repr(u8)]
#[derive(RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
enum Custody {
    Empty = 0,
    Seed(RedoubtArray<u8, 16>) = 1,
    Labelled {
        secret: RedoubtSecret<u128>,
        text: RedoubtString,
    } = 2,
}

fn seed() -> Custody {
    let mut array = RedoubtArray::default();

    an_array(&mut array);

    Custody::Seed(array)
}

fn labelled() -> Custody {
    let mut held_secret = RedoubtSecret::default();
    let mut held_text = RedoubtString::default();

    secret(&mut held_secret);
    a_text(&mut held_text);

    Custody::Labelled {
        secret: held_secret,
        text: held_text,
    }
}

/// The bytes encoding `custody` writes, for a decode to read.
fn encode(custody: &mut Custody) -> Result<Vec<u8>, AnyError> {
    let mut buffer = RedoubtCodecBuffer::with_capacity(custody.encode_bytes_required()?);

    custody.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds the tag's length to the live variant's."]
fn test_sizing_an_enum_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// encode_into
// ============================================================================

macro_rules! encoding_a_variant_is_found {
    ($($name:ident: $variant:ident => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let fill: fn() -> Custody = $fill;
                let mut custody = fill();
                let mut watch = Forensics::watching(&backwards())?;

                forensics!({
                    // Leaked and not a local: a local is dropped at the end of
                    // the block, and its drop empties or frees what the
                    // operation wrote before the photograph.
                    let buffer = Box::leak(Box::new(RedoubtCodecBuffer::with_capacity(
                        custody.encode_bytes_required()?,
                    )));

                    capture(|| custody.encode_into(buffer))?;

                    // What encode was given, emptied: what is found is what it
                    // wrote.
                    custody.fast_zeroize();
                });

                is_found(
                    &watch.snapshot()?,
                    concat!("a buffer the ", stringify!($variant), " variant was encoded into, and kept"),
                );

                Ok(())
            }
        )*
    };
}

encoding_a_variant_is_found! {
    test_what_encoding_wrote_of_a_seed_is_found_while_the_buffer_holds_it: Seed => seed;
    test_what_encoding_wrote_of_a_labelled_variant_is_found_while_the_buffer_holds_it:
        Labelled => labelled;
}

macro_rules! encoding_a_variant_leaves_nothing {
    ($($name:ident: $variant:ident => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let fill: fn() -> Custody = $fill;
                let mut custody = fill();

                forensics!({
                    let mut buffer =
                        RedoubtCodecBuffer::with_capacity(custody.encode_bytes_required()?);

                    capture(|| custody.encode_into(&mut buffer))?;

                    // CORRECTNESS: after the capture. A call made before it writes over the
                    // stack and the registers the operation left, and then the absence
                    // below is about that call and not about the operation.
                    buffer.fast_zeroize();

                    // Forgotten and not emptied: emptying it is the operation's.
                    core::mem::forget(custody);
                });

                leaves_nothing(
                    &report_before,
                    &watch.snapshot()?,
                    concat!("encoding the ", stringify!($variant), " variant"),
                );

                Ok(())
            }
        )*
    };
}

encoding_a_variant_leaves_nothing! {
    test_encoding_a_seed_leaves_nothing: Seed => seed;
    test_encoding_a_labelled_variant_leaves_nothing: Labelled => labelled;
}

#[redoubt_forensics::test]
fn test_encoding_an_enum_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut custody = labelled();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(custody.encode_bytes_required()? / 2);

        let refused = capture(|| custody.encode_into(&mut buffer));

        assert_eq!(
            refused.map_err(|error| error.to_string()),
            Err("RedoubtCodecBufferError: CapacityExceeded".to_string())
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((custody, buffer));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "encoding an enum into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// decode_from
// ============================================================================

macro_rules! decoding_a_variant_is_found {
    ($($name:ident: $variant:ident => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let fill: fn() -> Custody = $fill;
                let mut wire = encode(&mut fill())?;
                let mut watch = Forensics::watching(&backwards())?;

                forensics!({
                    // Leaked and not a local: a local is dropped at the end of
                    // the block, and its drop empties or frees what the
                    // operation wrote before the photograph.
                    let back = Box::leak(Box::new(Custody::Empty));

                    capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

                    // What decode was given, emptied: what is found is what it
                    // wrote.
                    wire.fast_zeroize();
                });

                is_found(
                    &watch.snapshot()?,
                    concat!("an enum the ", stringify!($variant), " variant was decoded into, and kept"),
                );

                Ok(())
            }
        )*
    };
}

decoding_a_variant_is_found! {
    test_what_decoding_wrote_of_a_seed_is_found_while_the_enum_holds_it: Seed => seed;
    test_what_decoding_wrote_of_a_labelled_variant_is_found_while_the_enum_holds_it:
        Labelled => labelled;
}

macro_rules! decoding_a_variant_over_another_leaves_nothing {
    ($($name:ident: $variant:ident over $held:ident => $fill:expr, $hold:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let fill: fn() -> Custody = $fill;
                let hold: fn() -> Custody = $hold;
                let mut wire = encode(&mut fill())?;
                let mut back = hold();

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
                    &watch.snapshot()?,
                    concat!(
                        "decoding the ",
                        stringify!($variant),
                        " variant over the ",
                        stringify!($held),
                        " variant",
                    ),
                );

                Ok(())
            }
        )*
    };
}

decoding_a_variant_over_another_leaves_nothing! {
    test_decoding_a_seed_leaves_nothing: Seed over Empty => seed, || Custody::Empty;
    test_decoding_a_labelled_variant_leaves_nothing: Labelled over Empty => labelled, || Custody::Empty;
    test_decoding_a_seed_over_a_labelled_variant_leaves_nothing:
        Seed over Labelled => seed, labelled;
    test_decoding_a_labelled_variant_over_a_seed_leaves_nothing:
        Labelled over Seed => labelled, seed;
    test_decoding_a_seed_over_a_seed_leaves_nothing: Seed over Seed => seed, seed;
}

#[redoubt_forensics::test]
fn test_decoding_an_enum_from_a_wire_cut_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = encode(&mut labelled())?;
    let half = wire.len() / 2;

    forensics!({
        let mut back = Custody::Empty;

        let refused = capture(|| back.decode_from(&mut &mut wire[..half]));

        assert!(
            matches!(refused, Err(DecodeError::PreconditionViolated)),
            "a wire cut short was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The half decode was never handed is the test's to empty.
        wire[half..].fast_zeroize();

        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "decoding an enum from a wire cut short",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_decoding_an_unknown_tag_over_an_enum_that_holds_a_secret_leaves_nothing()
-> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = encode(&mut seed())?;
    let mut back = labelled();

    wire[0] = 9;

    forensics!({
        let refused = capture(|| back.decode_from(&mut wire.as_mut_slice()));

        assert!(
            matches!(refused, Err(DecodeError::UnknownTag { tag: 9 })),
            "an unknown tag was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // What follows the tag decode never read is the test's to empty.
        wire[1..].fast_zeroize();

        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((back, wire));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "decoding an unknown tag over an enum that holds a secret",
    );

    Ok(())
}
