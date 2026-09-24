// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What making the master key leaves behind.
//!
//! The key does not exist until it is made, so its needle is read afterwards
//! and the block holds the bare freeze: the registers it reads are as the
//! reading left them, not as the making did.

use redoubt_forensics::{AnyError, Forensics, forensics, freeze};
use redoubt_zero::FastZeroizable;

use crate::master_key::buffer::create_initialized_buffer;
use crate::master_key::consts::MASTER_KEY_LEN;

use crate::tests::forensics::support::needles::backwards_through;
use crate::tests::forensics::support::{copying_into, is_found, leaves_nothing};

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
    let mut buffer = create_initialized_buffer();
    let mut watch = Forensics::watching(&backwards_through(|f| buffer.open(f))?)?;
    let mut kept = vec![0_u8; MASTER_KEY_LEN];

    buffer.open(&mut copying_into(&mut kept))?;

    forensics!({
        freeze!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key made, copied out of its page");

    kept.fast_zeroize();

    drop(core::hint::black_box((buffer, kept)));

    Ok(())
}

#[test]
fn test_making_the_key_leaves_nothing() -> Result<(), AnyError> {
    let mut buffer = create_initialized_buffer();
    let mut watch = Forensics::watching(&backwards_through(|f| buffer.open(f))?)?;

    let report_before = watch.snapshot()?;

    forensics!({
        freeze!();
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "the key made, read backwards",
        &report_after,
        "the key made",
    );

    drop(core::hint::black_box(buffer));

    Ok(())
}
