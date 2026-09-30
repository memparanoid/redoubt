// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, is_found, leaves_nothing};
use redoubt_zero::FastZeroizable;

use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::storage::open;

use crate::tests::forensics::support::copying_into;
use crate::tests::forensics::support::needles::backwards_through;

// ============================================================================
// open
// ============================================================================

#[redoubt_forensics::test]
fn test_the_key_opened_is_found_while_it_is_kept() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    forensics!({
        // Leaked and not a local: any call after the capture may write over
        // what a buffer let go of, and then the sweep genuinely does not find
        // what the operation wrote there.
        let kept = vec![0_u8; MASTER_KEY_LEN].leak();

        capture(|| open(&mut copying_into(kept)))?;
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key opened, and kept");

    Ok(())
}

#[redoubt_forensics::test]
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

    leaves_nothing(&report_before, &report_after, "the key opened");

    Ok(())
}
