// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::errors::{AnyError, Reason};
use crate::forensics::Forensics;

/// Thirty-two distinct bytes a test holds forwards on its own stack.
const HELD: [u8; 32] = [
    0x4E, 0x2B, 0xD7, 0x91, 0x35, 0xAC, 0x68, 0xF0, 0x1D, 0xB4, 0x7F, 0x02, 0xE6, 0x59, 0xA3, 0x18,
    0xCB, 0x74, 0x2D, 0x90, 0x46, 0xEF, 0x83, 0x1A, 0x57, 0xBC, 0x09, 0xD3, 0x6E, 0xF1, 0x24, 0xA7,
];

/// Thirty-two distinct bytes nothing in the process holds.
const ABSENT: [u8; 32] = [
    0x3A, 0xD5, 0x62, 0x0F, 0xB9, 0x47, 0xEC, 0x13, 0x8B, 0x26, 0xF4, 0x5D, 0xA0, 0x79, 0xC2, 0x1E,
    0x97, 0x6B, 0x04, 0xDE, 0x31, 0xAA, 0x58, 0xC7, 0x0B, 0xE3, 0x7C, 0x45, 0x9F, 0x12, 0xB6, 0x6A,
];

fn backwards(forwards: [u8; 32]) -> [u8; 32] {
    let mut needle = forwards;

    needle.reverse();

    needle
}

// ============================================================================
// Forensics::watching_each
// ============================================================================

#[test]
fn test_watching_each_reports_needle_for_no_needles_at_all() {
    assert!(matches!(Forensics::watching_each(&[]), Err(Reason::Needle)));
}

#[test]
fn test_watching_each_reports_needle_for_one_it_cannot_hold() {
    let absent = backwards(ABSENT);

    assert!(matches!(
        Forensics::watching_each(&[&absent, &[]]),
        Err(Reason::Needle)
    ));
}

// ============================================================================
// Forensics::snapshot
// ============================================================================

#[test]
fn test_snapshot_returns_the_report_of_the_first_needle() -> Result<(), AnyError> {
    let held = HELD;

    core::hint::black_box(&held);

    let (absent, present) = (backwards(ABSENT), backwards(HELD));

    let first_held = Forensics::watching_each(&[&present, &absent])?.snapshot()?;
    let first_absent = Forensics::watching_each(&[&absent, &present])?.snapshot()?;

    assert!(first_held.found, "the process holds the first needle");
    assert!(
        !first_absent.found,
        "the process does not hold the first needle"
    );

    Ok(())
}

// ============================================================================
// Forensics::snapshot_each
// ============================================================================

#[test]
fn test_snapshot_each_returns_a_report_for_each_needle_in_the_order_given() -> Result<(), AnyError>
{
    let held = HELD;

    core::hint::black_box(&held);

    let (absent, present) = (backwards(ABSENT), backwards(HELD));

    let reports = Forensics::watching_each(&[&absent, &present, &absent])?.snapshot_each()?;

    assert_eq!(reports.len(), 3);
    assert!(!reports[0].found, "the first is nowhere");
    assert!(reports[1].found, "the process holds the second");
    assert_eq!(reports[1].widest, 32);
    assert!(!reports[2].found, "the third is nowhere");

    Ok(())
}

#[test]
fn test_snapshot_each_weighs_every_needle_against_the_same_photograph() -> Result<(), AnyError> {
    let held = HELD;

    core::hint::black_box(&held);

    let (absent, present) = (backwards(ABSENT), backwards(HELD));

    let reports = Forensics::watching_each(&[&absent, &present])?.snapshot_each()?;

    assert_eq!(reports[0].swept, reports[1].swept);
    assert_ne!(reports[0].swept, 0);

    Ok(())
}
