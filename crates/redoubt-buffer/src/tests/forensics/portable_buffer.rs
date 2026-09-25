// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # A portable buffer never protects what it holds
//!
//! Its bytes are an ordinary heap allocation: readable by the sweep, and by
//! swap, a core dump or ptrace, for as long as the buffer holds them. It can
//! never give the protection a page buffer gives, and the section at rest says
//! so by finding the secret. What it does promise is that nothing is left once
//! it lets go.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::portable_buffer::PortableBuffer;
use crate::traits::Buffer;

use crate::tests::forensics::support::needles::{SECRET, backwards};
use crate::tests::forensics::support::{fill, hold_on, is_found, leaves_nothing, let_go, used};

// ============================================================================
// PortableBuffer, at rest
// ============================================================================

#[test]
fn test_the_secret_a_portable_buffer_holds_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = PortableBuffer::create(SECRET.len());

    fill(&mut held)?;

    let report = watch.snapshot()?;

    is_found(&report, "a portable buffer holding the secret");

    drop(held);

    Ok(())
}

// ============================================================================
// PortableBuffer, dropped
// ============================================================================

#[test]
fn test_dropping_a_portable_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PortableBuffer::create(SECRET.len());

        fill(&mut held)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(held));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a portable buffer dropped");

    Ok(())
}

// ============================================================================
// PortableBuffer, moved
// ============================================================================

#[test]
fn test_a_portable_buffer_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = PortableBuffer::create(SECRET.len());

        fill(&mut held)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a portable buffer given away, and kept");

    Ok(())
}

#[test]
fn test_a_portable_buffer_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PortableBuffer::create(SECRET.len());

        fill(&mut held)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(held));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a portable buffer given away",
    );

    Ok(())
}

// ============================================================================
// PortableBuffer::create
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty buffer."]
fn test_making_a_portable_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Debug for PortableBuffer
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints the length."]
fn test_printing_a_portable_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PortableBuffer::open
// ============================================================================

#[test]
fn test_a_portable_buffer_read_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = PortableBuffer::create(SECRET.len());

    fill(&mut held)?;

    forensics!({
        let read = capture(|| held.open(&mut used));

        read?;
    });

    let report = watch.snapshot()?;

    is_found(&report, "a portable buffer read, and kept");

    drop(held);

    Ok(())
}

#[test]
fn test_reading_a_portable_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = PortableBuffer::create(SECRET.len());

    fill(&mut held)?;

    forensics!({
        let read = capture(|| held.open(&mut used));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);

        read?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a portable buffer read");

    Ok(())
}

// ============================================================================
// PortableBuffer::open_mut
// ============================================================================

#[test]
fn test_a_portable_buffer_written_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = PortableBuffer::create(SECRET.len());

    forensics!({
        let wrote = capture(|| fill(&mut held));

        wrote?;
    });

    let report = watch.snapshot()?;

    is_found(&report, "a portable buffer written, and kept");

    drop(held);

    Ok(())
}

#[test]
fn test_writing_a_portable_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = PortableBuffer::create(SECRET.len());

    forensics!({
        let wrote = capture(|| fill(&mut held));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(held);

        wrote?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a portable buffer written");

    Ok(())
}

// ============================================================================
// PortableBuffer::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_reading_a_portable_buffer_length_leaves_nothing() {
    // Intentionally empty.
}
