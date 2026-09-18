// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the door decides before anything is derived.
//!
//! What it derives is settled against RFC 5869 and Wycheproof, which are
//! answers somebody published. The two refusals below are this crate's own, and
//! they are here because nobody publishes an answer for a length that has none.

use crate::consts::{HASH_SIZE, MAX_OUTPUT_SIZE};
use crate::error::HkdfError;
use crate::hkdf::hkdf;

// ============================================================================
// hkdf
// ============================================================================

/// One byte past the last block the counter has.
///
/// RFC 5869 §2.3 numbers the output blocks with one byte that starts at one, so
/// a caller served past the ceiling would be reading material the counter wrote
/// twice.
#[test]
fn test_hkdf_reports_output_too_long_one_byte_past_the_last_block() {
    let mut okm = [0_u8; MAX_OUTPUT_SIZE + 1];

    assert_eq!(
        hkdf(&[], &[0x11; 32], &[], &mut okm),
        Err(HkdfError::OutputTooLong),
    );
}

/// And the last block itself is served.
#[test]
fn test_hkdf_fills_output_of_exactly_the_last_block() {
    let mut okm = [0_u8; MAX_OUTPUT_SIZE];

    assert!(hkdf(&[], &[0x11; 32], &[], &mut okm).is_ok());
    assert!(
        okm[MAX_OUTPUT_SIZE - HASH_SIZE..]
            .iter()
            .any(|byte| *byte != 0),
        "the last block was counted and never written",
    );
}

/// Nothing asked for is nothing done, and not a refusal.
#[test]
fn test_hkdf_returns_ok_for_no_output_at_all() {
    assert!(hkdf(&[], &[0x11; 32], &[], &mut []).is_ok());
}
