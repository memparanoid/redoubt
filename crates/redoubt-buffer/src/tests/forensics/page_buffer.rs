// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! No section here has a presence: the page is out of the sweep's reach, so
//! there is no moment at which the secret can be photographed where a page
//! buffer keeps it. The absences rest on the instrument's own reach over
//! registers and the stack.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::page_buffer::PageBuffer;
use crate::traits::Buffer;

use crate::tests::forensics::support::needles::{SECRET, backwards};
use crate::tests::forensics::support::{fill, leaves_nothing, let_go, used};

// ============================================================================
// PageBuffer, dropped
// ============================================================================

#[test]
fn test_dropping_a_page_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PageBuffer::new(SECRET.len())?;

        fill(&mut held)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(held));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a page buffer dropped");

    Ok(())
}

// ============================================================================
// PageBuffer, moved
// ============================================================================

#[test]
fn test_a_page_buffer_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PageBuffer::new(SECRET.len())?;

        fill(&mut held)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(held));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a page buffer given away");

    Ok(())
}

// ============================================================================
// PageBuffer::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty, closed page."]
fn test_making_a_page_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PageBuffer::unseal
// ============================================================================

#[test]
#[ignore = "Reads no secret: it opens the page."]
fn test_unsealing_a_page_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PageBuffer::seal
// ============================================================================

#[test]
#[ignore = "Reads no secret: it closes the page, and where it cannot, writes zeros over it."]
fn test_sealing_a_page_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PageBuffer::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_asking_whether_a_page_buffer_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PageBuffer::open
// ============================================================================

#[test]
fn test_reading_a_page_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = PageBuffer::new(SECRET.len())?;

    fill(&mut held)?;

    forensics!({
        let read = capture(|| held.open(&mut used));

        read?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a page buffer read");

    core::hint::black_box(&held);

    Ok(())
}

// ============================================================================
// PageBuffer::open_mut
// ============================================================================

#[test]
fn test_writing_a_page_buffer_leaves_nothing_outside_the_page() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    forensics!({
        let mut held = PageBuffer::new(SECRET.len())?;

        let wrote = capture(|| fill(&mut held));

        wrote?;

        // CORRECTNESS: the page is left holding the secret, which is what the
        // absence below is about. Releasing it here empties and unmaps it, and
        // the absence is then about a page that is not there.
        core::mem::forget(held);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a page buffer written");

    Ok(())
}

// ============================================================================
// PageBuffer::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_reading_a_page_buffer_length_leaves_nothing() {
    // Intentionally empty.
}
