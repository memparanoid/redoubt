// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero_core::FastZeroizable;

use crate::support::needles::backwards;
use crate::support::{giving, leaves_nothing};

// ============================================================================
// [T]::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_slice_of_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = Box::new([0_u8; 32]);

    giving(&mut held[..]);

    forensics!({
        let slice: &mut [u8] = &mut held[..];

        capture(|| slice.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice of bytes zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_slice_of_boxes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut first = Box::new([0_u8; 32]);
    let mut second = Box::new([0_u8; 32]);

    giving(&mut first[..]);
    giving(&mut second[..]);

    let mut held = vec![first, second];

    forensics!({
        let slice: &mut [Box<[u8; 32]>] = &mut held[..];

        capture(|| slice.fast_zeroize());
    });

    core::mem::forget(held);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice of boxes zeroized");

    Ok(())
}
