// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a `RedoubtCodecBuffer` leaves behind.
//!
//! `write` is measured over a `u128`, the widest primitive, against sixteen
//! bytes of the secret.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;

use crate::tests::forensics::support::needles::{backwards, half_backwards};
use crate::tests::forensics::support::{
    a_buffer_holding, a_u128, hold_on, is_found, leaves_nothing, let_go, secret_bytes,
};

// ============================================================================
// RedoubtCodecBuffer::drop
// ============================================================================

#[test]
fn test_a_buffer_dropped_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let buffer = a_buffer_holding()?;

    forensics!({
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a buffer dropped",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer, moved
// ============================================================================

#[test]
fn test_a_buffer_given_away_is_found_while_it_is_kept() -> Result<(), AnyError> {
    let buffer = a_buffer_holding()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(buffer));
    });

    is_found(&watch.snapshot()?, "a buffer given away, and kept");

    Ok(())
}

#[test]
fn test_a_buffer_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let buffer = a_buffer_holding()?;

    forensics!({
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(buffer));
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a buffer given away",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer::debug_assert_invariant
// ============================================================================

#[test]
#[ignore = "Reads no secret: it compares the cursor with the capacity."]
fn test_asserting_the_invariant_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::with_capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty buffer."]
fn test_making_a_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::realloc_with_capacity
// ============================================================================

#[test]
fn test_reallocating_a_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut buffer = a_buffer_holding()?;

    forensics!({
        capture(|| buffer.realloc_with_capacity(64));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(buffer);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a buffer reallocated",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer::clear
// ============================================================================

#[test]
fn test_clearing_a_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut buffer = a_buffer_holding()?;

    forensics!({
        capture(|| buffer.clear());

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(buffer);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a buffer cleared",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer::as_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_reading_a_buffer_as_a_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::as_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_reading_a_buffer_as_a_mutable_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it measures the capacity."]
fn test_measuring_a_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it measures the capacity."]
fn test_asking_whether_a_buffer_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtCodecBuffer::write
// ============================================================================

#[test]
fn test_what_writing_a_value_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut value = a_u128();
    let mut watch = Forensics::watching(&half_backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| buffer.write(&mut *value))?;

        // Emptied, so what is found can only be what was written.
        value.fast_zeroize();

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer written, and kept");

    Ok(())
}

#[test]
fn test_writing_a_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut value = a_u128();

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(16);

        capture(|| buffer.write(&mut *value))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        value.fast_zeroize();
        buffer.fast_zeroize();

        drop(buffer);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a value written",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer::write_slice
// ============================================================================

#[test]
fn test_what_writing_a_slice_wrote_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    let mut source = secret_bytes(32);
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(32);

        capture(|| buffer.write_slice(&mut source))?;

        // Emptied, so what is found can only be what was written.
        source.fast_zeroize();

        core::mem::forget(buffer);
    });

    is_found(&watch.snapshot()?, "a buffer written, and kept");

    Ok(())
}

#[test]
fn test_writing_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = secret_bytes(32);

    forensics!({
        let mut buffer = RedoubtCodecBuffer::with_capacity(32);

        capture(|| buffer.write_slice(&mut source))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        source.fast_zeroize();
        buffer.fast_zeroize();

        drop(buffer);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a slice written",
    );

    Ok(())
}

// ============================================================================
// RedoubtCodecBuffer::export_as_vec
// ============================================================================

#[test]
fn test_what_exporting_wrote_is_found_while_the_vec_holds_it() -> Result<(), AnyError> {
    let mut buffer = a_buffer_holding()?;
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let exported = capture(|| buffer.export_as_vec());

        core::mem::forget(exported);
    });

    is_found(&watch.snapshot()?, "a buffer exported, and kept");

    drop(buffer);

    Ok(())
}

#[test]
fn test_exporting_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut buffer = a_buffer_holding()?;

    forensics!({
        let mut exported = capture(|| buffer.export_as_vec());

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        exported.fast_zeroize();

        // Forgotten and not emptied: emptying it is the operation's.
        core::mem::forget(buffer);
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a buffer exported",
    );

    Ok(())
}
