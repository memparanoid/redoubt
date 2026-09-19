// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every region of both functions, at `Narrow` and at nothing else.
//!
//! What this crate reads on its own has to be 100%, or a drop measured later
//! says only that these tests were thin.

use crate::{Counted, Narrow, Refused, Wide, halved, twice_halved};

// === === === === === === === === === ===
// count
// === === === === === === === === === ===

/// Both impls are called straight, so that what the generic is instantiated at
/// is the only thing `test-b` adds.
#[test]
fn test_count_answers_what_each_width_holds() {
    assert_eq!(Narrow(7).count(), 7);
    assert_eq!(Wide(7).count(), 7);
}

// === === === === === === === === === ===
// halved
// === === === === === === === === === ===

#[test]
fn test_halved_reports_zero_for_nothing() {
    assert_eq!(halved(&Narrow(0)), Err(Refused::Zero));
}

#[test]
fn test_halved_answers_half() {
    assert_eq!(halved(&Narrow(8)), Ok(4));
}

// === === === === === === === === === ===
// twice_halved
// === === === === === === === === === ===

#[test]
fn test_twice_halved_propagates_zero() {
    assert_eq!(twice_halved(&Narrow(0)), Err(Refused::Zero));
}

#[test]
fn test_twice_halved_reports_too_many() {
    assert_eq!(twice_halved(&Narrow(200)), Err(Refused::TooMany));
}

#[test]
fn test_twice_halved_answers_a_quarter() {
    assert_eq!(twice_halved(&Narrow(8)), Ok(2));
}
