// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What opening the key through the spinlock storage leaves behind.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::storage::portable::open;

use crate::tests::forensics::support::needles::backwards_through;
use crate::tests::forensics::support::{copying_into, is_found, leaves_nothing};

// ============================================================================
// init_slow
// ============================================================================

#[test]
#[ignore = "Reads no secret: it stores the buffer create_initialized_buffer makes."]
fn test_initializing_the_storage_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// acquire
// ============================================================================

#[test]
#[ignore = "Reads no secret: it spins on a flag."]
fn test_acquiring_the_lock_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// release
// ============================================================================

#[test]
#[ignore = "Reads no secret: it clears a flag."]
fn test_releasing_the_lock_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// open
// ============================================================================

#[test]
fn test_the_key_opened_is_found_while_it_is_kept() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;
    let mut kept = vec![0_u8; MASTER_KEY_LEN];

    forensics!({
        capture(|| open(&mut copying_into(&mut kept)))?;

        core::mem::forget(kept);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key opened, and kept");

    Ok(())
}

#[test]
fn test_opening_the_key_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    let report_before = watch.snapshot()?;

    let mut kept = vec![0_u8; MASTER_KEY_LEN];

    forensics!({
        capture(|| open(&mut copying_into(&mut kept)))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        kept.fast_zeroize();
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        "the key opened",
    );

    drop(core::hint::black_box(kept));

    Ok(())
}
