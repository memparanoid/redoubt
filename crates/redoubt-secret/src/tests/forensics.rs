// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a secret leaves behind on its way into the box that holds it, and out.
//!
//! No test here is about a `u64`: eight bytes is `QUIET`, the width memory
//! reaches by accident, so an absence over it is no answer. The narrowest
//! primitive measured is a `u128`, and the `u64` a caller stores runs the same
//! generic code.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

use redoubt_codec::{BytesRequired, Decode, Encode, EncodeError, RedoubtCodecBuffer};
use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::RedoubtSecret;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A second secret, sharing no run with [`SECRET`], for the value a replace
/// puts where that one was.
const OTHER: [u8; 32] = [
    0x27, 0xC8, 0x6B, 0x15, 0xE0, 0x93, 0x4D, 0xFA, 0x3E, 0x81, 0xD6, 0x09, 0xB2, 0x5F, 0x74, 0xAB,
    0x10, 0xE9, 0x36, 0x8C, 0x57, 0xF2, 0x0B, 0xC4, 0x69, 0xAD, 0x22, 0x9B, 0x40, 0xDD, 0x78, 0x05,
];

/// Sixteen distinct bytes as a `u128`, the narrowest primitive an absence can
/// be measured over.
const NARROW: u128 = u128::from_le_bytes([
    0x3B, 0xD5, 0x62, 0xF7, 0x18, 0xAC, 0x4E, 0x90, 0x27, 0xEB, 0x5D, 0x81, 0xC6, 0x0F, 0xA3, 0x74,
]);

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The `u128` needle, built the same way and for the same reason.
fn narrow_backwards() -> Vec<u8> {
    NARROW.to_le_bytes().iter().rev().copied().collect()
}

/// A secret into somewhere the caller already owns, by the copy that erases
/// what it used.
///
/// Not a plain assignment, which is whatever move the compiler emits: the test
/// does not get to cause the thing it is measuring.
fn giving(into: &mut [u8; 32], from: &[u8; 32]) {
    // SAFETY: both are thirty-two bytes, and a constant and a local are
    // different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };
}

/// A secret holding `from`, filled by the copy that erases what it used.
fn holding(from: &[u8; 32]) -> RedoubtSecret<[u8; 32]> {
    let mut source = [0_u8; 32];

    giving(&mut source, from);

    RedoubtSecret::from(&mut source)
}

/// The wire a secret holding `from` encodes into.
fn wire(from: &[u8; 32]) -> Result<Vec<u8>, AnyError> {
    let mut held = holding(from);
    let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

    held.encode_into(&mut buffer)?;

    Ok(buffer.export_as_vec())
}

/// Takes the value and lets it go, which runs its drop somewhere the caller
/// cannot see.
///
/// Not inlined: a move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value the same way and never lets it go.
///
/// The move is the same move as [`let_go`]'s, so whatever it leaves behind is
/// the same; what changes is that whoever took it still holds the secret when
/// the photograph is taken.
#[inline(never)]
fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// Without a presence an absence cannot be told apart from a sweep that reaches
/// nowhere.
fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// The whole secret is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing taken yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// RedoubtSecret, dropped
// ============================================================================

#[test]
fn test_dropping_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let held = RedoubtSecret::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(held));
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret dropped");

    Ok(())
}

// ============================================================================
// RedoubtSecret, moved
// ============================================================================

#[test]
fn test_a_secret_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let held = RedoubtSecret::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    is_found(&watch.snapshot()?, "a secret given away, and kept");

    Ok(())
}

/// What a move copies is the box's address and not what is behind it, so the
/// slot left behind holds no secret. Read a failure as the value having come
/// out of the box and into the struct, where a move carries the bytes and
/// empties nothing.
#[test]
fn test_a_secret_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let held = RedoubtSecret::from(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(held));
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret given away");

    Ok(())
}

// ============================================================================
// FastZeroizable for RedoubtSecret
// ============================================================================

#[test]
fn test_zeroizing_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    let mut held = RedoubtSecret::from(&mut source);

    forensics!({
        capture(|| held.fast_zeroize());
    });

    // Not dropped: the drop zeroizes again, and would keep this absence green
    // with the operation's own wipe deleted.
    core::mem::forget(held);

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret zeroized");

    Ok(())
}

// ============================================================================
// BytesRequired for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it adds lengths."]
fn test_sizing_a_secret_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Encode for RedoubtSecret
// ============================================================================

#[test]
fn test_what_encoding_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = holding(&SECRET);

    forensics!({
        // Leaked and not a local: any call after the capture may write over
        // what a buffer let go of, and then the sweep genuinely does not find
        // what the operation wrote there.
        let buffer = Box::leak(Box::new(RedoubtCodecBuffer::with_capacity(
            held.encode_bytes_required()?,
        )));

        capture(|| held.encode_into(buffer))?;

        // What encode was given, emptied: what is found is what it wrote.
        held.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a buffer a secret was encoded into, and kept");

    Ok(())
}

#[test]
fn test_encoding_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = holding(&SECRET);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()?);

        capture(|| held.encode_into(&mut buffer))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        buffer.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret encoded");

    Ok(())
}

#[test]
fn test_encoding_a_secret_into_a_buffer_too_small_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = holding(&SECRET);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(held.encode_bytes_required()? / 2);

        let refused = capture(|| held.encode_into(&mut buffer));

        assert!(
            matches!(refused, Err(EncodeError::RedoubtCodecBufferError(_))),
            "a buffer too small was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((held, buffer));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret encoded into a buffer too small",
    );

    Ok(())
}

// ============================================================================
// Decode for RedoubtSecret
// ============================================================================

#[test]
fn test_what_decoding_wrote_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut wire = wire(&SECRET)?;

    forensics!({
        // Leaked and not a local: any call after the capture may write over
        // what a secret let go of, and then the sweep genuinely does not find
        // what the operation wrote there.
        let back = Box::leak(Box::new(RedoubtSecret::<[u8; 32]>::default()));

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // What decode was given, emptied: what is found is what it wrote.
        wire.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a secret decoded into, and kept");

    Ok(())
}

#[test]
fn test_decoding_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&SECRET)?;

    forensics!({
        let mut back = RedoubtSecret::<[u8; 32]>::default();

        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(back);

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret decoded");

    Ok(())
}

/// The value the secret held before is what is watched for, and the secret is
/// kept holding the one decoded: nothing of the old may be left anywhere.
#[test]
fn test_decoding_over_a_secret_that_holds_one_leaves_nothing_of_the_old() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&OTHER)?;
    let mut back = holding(&SECRET);

    forensics!({
        capture(|| back.decode_from(&mut wire.as_mut_slice()))?;

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(wire);
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret decoded over one it held",
    );

    drop(back);

    Ok(())
}

#[test]
fn test_decoding_a_secret_from_a_wire_cut_short_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut wire = wire(&SECRET)?;
    let half = wire.len() / 2;

    forensics!({
        let mut back = RedoubtSecret::<[u8; 32]>::default();

        let refused = capture(|| back.decode_from(&mut &mut wire[..half]));

        assert!(refused.is_err(), "a wire cut short was not refused");

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
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
        "a secret decoded from a wire cut short",
    );

    Ok(())
}

// ============================================================================
// Default for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it boxes an empty value."]
fn test_making_an_empty_secret_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Debug for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints a placeholder."]
fn test_printing_a_secret_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtSecret::from
// ============================================================================

#[test]
fn test_what_was_taken_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        hold_on(held);
    });

    is_found(&watch.snapshot()?, "a secret taken from a source, and kept");

    Ok(())
}

#[test]
fn test_taking_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret taken");

    Ok(())
}

#[test]
fn test_taking_a_narrow_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&narrow_backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = NARROW;

    forensics!({
        let held = capture(|| RedoubtSecret::from(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a primitive secret taken",
    );

    Ok(())
}

// ============================================================================
// RedoubtSecret::replace
// ============================================================================

#[test]
fn test_what_replaced_is_found_while_the_secret_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let mut held = RedoubtSecret::<[u8; 32]>::default();

        capture(|| held.replace(&mut source));

        hold_on(held);
    });

    is_found(&watch.snapshot()?, "a secret replaced into, and kept");

    Ok(())
}

#[test]
fn test_replacing_a_secret_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source, &SECRET);

    forensics!({
        let mut held = RedoubtSecret::<[u8; 32]>::default();

        capture(|| held.replace(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);
    });

    leaves_nothing(&report_before, &watch.snapshot()?, "a secret replaced");

    Ok(())
}

/// The value the secret held before is what is watched for, and the secret is
/// kept holding the new one: nothing of the old may be left anywhere.
#[test]
fn test_replacing_a_secret_that_holds_one_leaves_nothing_of_the_old() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut old = [0_u8; 32];
    let mut new = [0_u8; 32];

    giving(&mut old, &SECRET);
    giving(&mut new, &OTHER);

    let mut held = RedoubtSecret::from(&mut old);

    forensics!({
        capture(|| held.replace(&mut new));
    });

    leaves_nothing(
        &report_before,
        &watch.snapshot()?,
        "a secret replaced over one it held",
    );

    drop(held);

    Ok(())
}

// ============================================================================
// AsRef for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_viewing_a_secret_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AsMut for RedoubtSecret
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_viewing_a_secret_mutably_leaves_nothing() {
    // Intentionally empty.
}
