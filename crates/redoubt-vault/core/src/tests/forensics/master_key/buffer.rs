// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What making the master key leaves behind.
//!
//! The key does not exist until it is made, so its needle is read out of the
//! page after the capture, and nothing photographs the process before: an
//! absence here asserts no copy and no run wider than `QUIET`, not an unmoved
//! score.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, pick_spiller};
use redoubt_zero::FastZeroizable;

use crate::master_key::buffer::create_initialized_buffer;
use crate::master_key::consts::MASTER_KEY_LEN;

use crate::tests::forensics::support::needles::backwards_through;
use crate::tests::forensics::support::{copying_into, is_found, leaves_no_copy};

// ============================================================================
// create_buffer
// ============================================================================

#[test]
#[ignore = "Reads no secret: it maps an empty page."]
fn test_making_a_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// create_initialized_buffer
// ============================================================================

/// The page the key is made in is guarded, and a guarded page is never swept.
#[test]
fn test_the_key_made_is_found_once_copied_out_of_its_page() -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let mut buffer;

    forensics!({
        buffer = capture(create_initialized_buffer);
    });

    let mut kept = vec![0_u8; MASTER_KEY_LEN];

    buffer.open(&mut copying_into(&mut kept))?;

    let mut watch = Forensics::watching(&backwards_through(|f| buffer.open(f))?)?;

    let report = watch.snapshot()?;

    is_found(&report, "the key made, copied out of its page");

    kept.fast_zeroize();

    drop(core::hint::black_box((buffer, kept)));

    Ok(())
}

#[test]
fn test_making_the_key_leaves_nothing() -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let mut buffer;

    forensics!({
        buffer = capture(create_initialized_buffer);
    });

    // CORRECTNESS: after the capture. A call made before it writes over the
    // stack and the registers the operation left, and then the absence below is
    // about that call and not about the operation.
    let mut watch = Forensics::watching(&backwards_through(|f| buffer.open(f))?)?;

    let report = watch.snapshot()?;

    leaves_no_copy(&report, "the key made");

    drop(core::hint::black_box(buffer));

    Ok(())
}
