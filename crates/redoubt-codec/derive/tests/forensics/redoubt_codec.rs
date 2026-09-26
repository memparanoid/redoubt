// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::{AllockedVec, RedoubtArray, RedoubtOption, RedoubtString, RedoubtVec};
use redoubt_codec_core::{BytesRequired, Decode, Encode, EncodeError, RedoubtCodecBuffer};
use redoubt_codec_derive::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_secret::RedoubtSecret;
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::support::needles::{NEEDLE, backwards};
use crate::support::{a_u128, bytes, giving, is_found, leaves_nothing, text};

/// What a container that can hold more than one needle is filled with.
const WIDE: usize = 8 * NEEDLE.len();

/// A struct nested in another: by value, boxed, and optional.
#[derive(Default, RedoubtZero, RedoubtCodec)]
struct Keys {
    secret: RedoubtSecret<u128>,
    array: RedoubtArray<u8, 16>,
    text: RedoubtString,
}

/// Every container the derive may be handed as a field, each filled with the
/// needle, so an absence over it is red if any one of them keeps it.
#[derive(Default, RedoubtZero, RedoubtCodec)]
struct Arsenal {
    secret: RedoubtSecret<u128>,
    maybe_secret: RedoubtOption<RedoubtSecret<u128>>,
    maybe_text: RedoubtOption<RedoubtString>,
    text: RedoubtString,
    bytes: RedoubtVec<u8>,
    array: RedoubtArray<u8, 16>,
    allocked: AllockedVec<u8>,
    keys: Keys,
    boxed_keys: Box<Keys>,
    maybe_keys: RedoubtOption<Keys>,
}

fn secret(into: &mut RedoubtSecret<u128>) {
    into.replace(&mut *a_u128());
}

fn maybe_secret(into: &mut RedoubtOption<RedoubtSecret<u128>>) {
    let mut held = RedoubtSecret::default();

    secret(&mut held);
    into.replace(&mut held);
}

fn a_text(into: &mut RedoubtString) {
    into.replace_from_mut_string(&mut text(WIDE));
}

fn maybe_text(into: &mut RedoubtOption<RedoubtString>) {
    let mut held = RedoubtString::default();

    a_text(&mut held);
    into.replace(&mut held);
}

fn some_bytes(into: &mut RedoubtVec<u8>) {
    into.replace_from_mut_slice(&mut bytes(WIDE));
}

fn an_array(into: &mut RedoubtArray<u8, 16>) {
    let mut held = Box::new([0_u8; 16]);

    giving(&mut *held);
    into.replace_from_mut_array(&mut held);
}

fn allocked(into: &mut AllockedVec<u8>) -> Result<(), AnyError> {
    into.realloc_with_capacity(WIDE);
    into.drain_from(&mut bytes(WIDE))?;

    Ok(())
}

fn keys(into: &mut Keys) {
    secret(&mut into.secret);
    an_array(&mut into.array);
    a_text(&mut into.text);
}

fn boxed_keys(into: &mut Box<Keys>) {
    keys(into);
}

fn maybe_keys(into: &mut RedoubtOption<Keys>) {
    let mut held = Keys::default();

    keys(&mut held);
    into.replace(&mut held);
}

fn arming(arsenal: &mut Arsenal) -> Result<(), AnyError> {
    secret(&mut arsenal.secret);
    maybe_secret(&mut arsenal.maybe_secret);
    maybe_text(&mut arsenal.maybe_text);
    a_text(&mut arsenal.text);
    some_bytes(&mut arsenal.bytes);
    an_array(&mut arsenal.array);
    allocked(&mut arsenal.allocked)?;
    keys(&mut arsenal.keys);
    boxed_keys(&mut arsenal.boxed_keys);
    maybe_keys(&mut arsenal.maybe_keys);

    Ok(())
}

fn armed_wire() -> Result<Vec<u8>, AnyError> {
    let mut source = Arsenal::default();

    arming(&mut source)?;

    wire(&mut source)
}

fn wire(arsenal: &mut Arsenal) -> Result<Vec<u8>, AnyError> {
    let mut buffer = RedoubtCodecBuffer::with_capacity(arsenal.encode_bytes_required()?);

    arsenal.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

// ============================================================================
// encode_bytes_required
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds lengths."]
fn test_sizing_a_struct_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// encode_into
// ============================================================================

macro_rules! encoding_one_field_is_found {
    ($($name:ident: $field:ident => $fill:expr;)*) => {
        $(
            #[test]
            fn $name() -> Result<(), AnyError> {
                let mut arsenal = Arsenal::default();
                let fill: fn(&mut Arsenal) -> Result<(), AnyError> = $fill;

                fill(&mut arsenal)?;

                let mut watch = Forensics::watching(&backwards())?;

                forensics!({
                    // Leaked and not a local: any call after the capture may
                    // write over what a buffer let go of, and then the sweep
                    // genuinely does not find what the operation wrote there.
                    let buffer = Box::leak(Box::new(RedoubtCodecBuffer::with_capacity(
                        arsenal.encode_bytes_required()?,
                    )));

                    capture(|| arsenal.encode_into(buffer))?;

                    // What encode was given, emptied: what is found is what it
                    // wrote.
                    arsenal.fast_zeroize();
                });

                is_found(
                    &watch.snapshot()?,
                    concat!("a buffer the ", stringify!($field), " was encoded into, and kept"),
                );

                Ok(())
            }
        )*
    };
}

encoding_one_field_is_found! {
    test_what_encoding_wrote_of_a_secret_is_found_while_the_buffer_holds_it:
        secret => |arsenal| { secret(&mut arsenal.secret); Ok(()) };
    test_what_encoding_wrote_of_an_optional_secret_is_found_while_the_buffer_holds_it:
        maybe_secret => |arsenal| { maybe_secret(&mut arsenal.maybe_secret); Ok(()) };
    test_what_encoding_wrote_of_an_optional_text_is_found_while_the_buffer_holds_it:
        maybe_text => |arsenal| { maybe_text(&mut arsenal.maybe_text); Ok(()) };
    test_what_encoding_wrote_of_a_text_is_found_while_the_buffer_holds_it:
        text => |arsenal| { a_text(&mut arsenal.text); Ok(()) };
    test_what_encoding_wrote_of_bytes_is_found_while_the_buffer_holds_it:
        bytes => |arsenal| { some_bytes(&mut arsenal.bytes); Ok(()) };
    test_what_encoding_wrote_of_an_array_is_found_while_the_buffer_holds_it:
        array => |arsenal| { an_array(&mut arsenal.array); Ok(()) };
    test_what_encoding_wrote_of_an_allocked_vec_is_found_while_the_buffer_holds_it:
        allocked => |arsenal| allocked(&mut arsenal.allocked);
    test_what_encoding_wrote_of_a_nested_struct_is_found_while_the_buffer_holds_it:
        keys => |arsenal| { keys(&mut arsenal.keys); Ok(()) };
    test_what_encoding_wrote_of_a_boxed_struct_is_found_while_the_buffer_holds_it:
        boxed_keys => |arsenal| { boxed_keys(&mut arsenal.boxed_keys); Ok(()) };
    test_what_encoding_wrote_of_an_optional_struct_is_found_while_the_buffer_holds_it:
        maybe_keys => |arsenal| { maybe_keys(&mut arsenal.maybe_keys); Ok(()) };
}

#[test]
fn test_encoding_a_struct_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut arsenal = Arsenal::default();

    arming(&mut arsenal)?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(arsenal.encode_bytes_required()?);

        capture(|| arsenal.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(arsenal);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding a struct",
    );

    Ok(())
}

#[test]
fn test_encoding_a_struct_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut arsenal = Arsenal::default();

    arming(&mut arsenal)?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(arsenal.encode_bytes_required()? / 2);

        let refused = capture(|| arsenal.encode_into(&mut buffer));

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((arsenal, buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "encoding a struct into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// decode_from
// ============================================================================

macro_rules! decoding_one_field_is_found {
    ($($name:ident: $field:ident => $fill:expr;)*) => {
        $(
            #[test]
            fn $name() -> Result<(), AnyError> {
                let mut arsenal = Arsenal::default();
                let fill: fn(&mut Arsenal) -> Result<(), AnyError> = $fill;

                fill(&mut arsenal)?;

                let mut wire = wire(&mut arsenal)?;
                let mut watch = Forensics::watching(&backwards())?;

                forensics!({
                    // Leaked and not a local: any call after the capture may
                    // write over what a struct let go of, and then the sweep
                    // genuinely does not find what the operation wrote there.
                    let back = Box::leak(Box::new(Arsenal::default()));

                    capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

                    // What decode was given, emptied: what is found is what it
                    // wrote.
                    wire.fast_zeroize();
                });

                is_found(
                    &watch.snapshot()?,
                    concat!("a struct the ", stringify!($field), " was decoded into, and kept"),
                );

                Ok(())
            }
        )*
    };
}

decoding_one_field_is_found! {
    test_what_decoding_wrote_of_a_secret_is_found_while_the_struct_holds_it:
        secret => |arsenal| { secret(&mut arsenal.secret); Ok(()) };
    test_what_decoding_wrote_of_an_optional_secret_is_found_while_the_struct_holds_it:
        maybe_secret => |arsenal| { maybe_secret(&mut arsenal.maybe_secret); Ok(()) };
    test_what_decoding_wrote_of_an_optional_text_is_found_while_the_struct_holds_it:
        maybe_text => |arsenal| { maybe_text(&mut arsenal.maybe_text); Ok(()) };
    test_what_decoding_wrote_of_a_text_is_found_while_the_struct_holds_it:
        text => |arsenal| { a_text(&mut arsenal.text); Ok(()) };
    test_what_decoding_wrote_of_bytes_is_found_while_the_struct_holds_it:
        bytes => |arsenal| { some_bytes(&mut arsenal.bytes); Ok(()) };
    test_what_decoding_wrote_of_an_array_is_found_while_the_struct_holds_it:
        array => |arsenal| { an_array(&mut arsenal.array); Ok(()) };
    test_what_decoding_wrote_of_an_allocked_vec_is_found_while_the_struct_holds_it:
        allocked => |arsenal| allocked(&mut arsenal.allocked);
    test_what_decoding_wrote_of_a_nested_struct_is_found_while_the_struct_holds_it:
        keys => |arsenal| { keys(&mut arsenal.keys); Ok(()) };
    test_what_decoding_wrote_of_a_boxed_struct_is_found_while_the_struct_holds_it:
        boxed_keys => |arsenal| { boxed_keys(&mut arsenal.boxed_keys); Ok(()) };
    test_what_decoding_wrote_of_an_optional_struct_is_found_while_the_struct_holds_it:
        maybe_keys => |arsenal| { maybe_keys(&mut arsenal.maybe_keys); Ok(()) };
}

#[test]
fn test_decoding_a_struct_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = armed_wire()?;

    forensics!({
        let mut back = Arsenal::default();

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
        "decoding a struct",
    );

    Ok(())
}

#[test]
fn test_decoding_a_struct_over_one_that_holds_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = armed_wire()?;
    let mut back = Arsenal::default();

    arming(&mut back)?;

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
        "decoding a struct over one that holds a secret",
    );

    Ok(())
}

#[test]
fn test_decoding_a_struct_from_a_wire_cut_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = armed_wire()?;
    let half = wire.len() / 2;

    forensics!({
        let mut back = Arsenal::default();

        let refused = capture(|| back.decode_from(&mut &mut wire[..half]));

        assert!(refused.is_err(), "a wire cut short was not refused");

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
        "nothing held yet",
        &watch.snapshot()?,
        "decoding a struct from a wire cut short",
    );

    Ok(())
}
