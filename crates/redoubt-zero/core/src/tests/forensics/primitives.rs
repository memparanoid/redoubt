// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Measured on `u128`, the widest: a narrower integer is a run no wider than
//! what memory holds by chance.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::{FastZeroizable, ZeroizationProbe};

use crate::tests::forensics::support::needles::SECRET;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

fn half_backwards() -> Vec<u8> {
    SECRET[..16].iter().rev().copied().collect()
}

fn a_u128() -> Box<u128> {
    let mut value = Box::new(0_u128);

    // SAFETY: a `u128` is sixteen initialised bytes, and the box is the only
    // reference to them.
    let bytes = unsafe { core::slice::from_raw_parts_mut((&raw mut *value).cast::<u8>(), 16) };

    giving(bytes);

    value
}

// ============================================================================
// u128::is_zeroized
// ============================================================================

#[test]
fn test_a_u128_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let held = a_u128();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a u128 probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_a_u128_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_u128();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a u128 probed");

    Ok(())
}

// ============================================================================
// bool::is_zeroized
// ============================================================================

#[test]
#[ignore = "Unmeasurable: one byte is a run memory holds by chance."]
fn test_probing_a_bool_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// char::is_zeroized
// ============================================================================

#[test]
#[ignore = "Unmeasurable: four bytes are a run memory holds by chance."]
fn test_probing_a_char_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// u128::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_u128_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&half_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_u128();

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a u128 zeroized");

    Ok(())
}

// ============================================================================
// ()::fast_zeroize
// ============================================================================

#[test]
#[ignore = "Reads no secret: the unit type holds nothing."]
fn test_zeroizing_the_unit_type_leaves_nothing() {
    // Intentionally empty.
}
