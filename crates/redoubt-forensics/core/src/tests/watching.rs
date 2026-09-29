// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::errors::{AnyError, Reason};
use crate::watching::Watching;

const HELD: [u8; 32] = [
    0x4E, 0x2B, 0xD7, 0x91, 0x35, 0xAC, 0x68, 0xF0, 0x1D, 0xB4, 0x7F, 0x02, 0xE6, 0x59, 0xA3, 0x18,
    0xCB, 0x74, 0x2D, 0x90, 0x46, 0xEF, 0x83, 0x1A, 0x57, 0xBC, 0x09, 0xD3, 0x6E, 0xF1, 0x24, 0xA7,
];

const ABSENT: [u8; 32] = [
    0x3A, 0xD5, 0x62, 0x0F, 0xB9, 0x47, 0xEC, 0x13, 0x8B, 0x26, 0xF4, 0x5D, 0xA0, 0x79, 0xC2, 0x1E,
    0x97, 0x6B, 0x04, 0xDE, 0x31, 0xAA, 0x58, 0xC7, 0x0B, 0xE3, 0x7C, 0x45, 0x9F, 0x12, 0xB6, 0x6A,
];

const OTHER: [u8; 32] = [
    0xC1, 0x5E, 0x28, 0x93, 0x7A, 0x0D, 0xF6, 0x44, 0xB0, 0x39, 0xE2, 0x87, 0x1C, 0x65, 0xDA, 0x0E,
    0x72, 0xAF, 0x16, 0xCD, 0x53, 0x98, 0x2F, 0xE8, 0x07, 0xBE, 0x61, 0x34, 0xF9, 0x8C, 0x25, 0xD0,
];

fn backwards(forwards: [u8; 32]) -> [u8; 32] {
    let mut needle = forwards;

    needle.reverse();

    needle
}

// ============================================================================
// Watching::start
// ============================================================================

#[test]
fn test_start_propagates_the_refusal_of_no_needles_at_all() {
    assert!(matches!(Watching::start(&[]), Err(Reason::Needle)));
}

#[test]
fn test_start_propagates_the_refusal_of_a_needle_of_nothing() {
    let absent = backwards(ABSENT);

    assert!(matches!(
        Watching::start(&[("absent", &absent), ("nothing", &[])]),
        Err(Reason::Needle)
    ));
}

// ============================================================================
// Watching::none_left
// ============================================================================

#[test]
#[should_panic(expected = "an operation, of the held")]
fn test_none_left_refuses_a_needle_the_process_holds_and_names_it() {
    let (absent, present, other) = (backwards(ABSENT), backwards(HELD), backwards(OTHER));

    let mut watching =
        Watching::start(&[("absent", &absent), ("held", &present), ("other", &other)])
            .expect("the needles should be ones the instrument can hold");

    let held = HELD;

    core::hint::black_box(&held);

    watching
        .none_left("an operation")
        .expect("the photograph should be taken");
}

#[test]
fn test_none_left_accepts_a_process_holding_none_of_the_needles() -> Result<(), AnyError> {
    let (absent, other) = (backwards(ABSENT), backwards(OTHER));

    let mut watching = Watching::start(&[("absent", &absent), ("other", &other)])?;

    watching.none_left("an operation")?;

    Ok(())
}
