// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the door decides before anything is derived, and that it is the door it
//! says it is.
//!
//! What it derives is settled against RFC 5869 and Wycheproof, which are
//! answers somebody published. The refusals below are this crate's own, because
//! nobody publishes an answer for a length that has none.
//!
//! # Why the sameness is generated rather than written down
//!
//! Every published answer goes to the struct, and the function is what a caller
//! actually reaches. What sits between them is one line, and a fixed case that
//! checked it would be satisfied by any second implementation that agreed on
//! that one input. Over arbitrary inputs there is nothing left for a second
//! implementation to be: it either forwards or it is caught.

use alloc::vec;

use proptest::prelude::*;

use crate::consts::{HASH_SIZE, MAX_OUTPUT_SIZE};
use crate::error::HkdfError;
use crate::hkdf::{HkdfSha256, hkdf};

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

/// The last block the counter has is served rather than counted and skipped.
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

proptest! {
    /// What the function leaves in the destination is what the struct leaves,
    /// for whatever it is given.
    ///
    /// This is what says the published answers reach the exported door. They
    /// are all put to the struct, and a function that stopped forwarding — a
    /// second derivation, an argument transposed, a default that drifted —
    /// would keep every one of them green.
    #[test]
    fn test_hkdf_writes_what_the_struct_derives(
        salt in prop::collection::vec(any::<u8>(), 0..96),
        ikm in prop::collection::vec(any::<u8>(), 0..96),
        info in prop::collection::vec(any::<u8>(), 0..96),
        wanted in 0_usize..320,
    ) {
        let mut through_the_door = vec![0_u8; wanted];
        let mut through_the_struct = vec![0_u8; wanted];

        let door = hkdf(&salt, &ikm, &info, &mut through_the_door);
        let derived = HkdfSha256::new().derive(&salt, &ikm, &info, &mut through_the_struct);

        prop_assert_eq!(door, derived);
        prop_assert_eq!(through_the_door, through_the_struct);
    }

    /// A length that has no block is refused by the function where the struct
    /// refuses it.
    ///
    /// The ceiling is the one decision the function could make on its own
    /// rather than pass along, so it is asked separately: a door that refused
    /// where the struct does not, or served where the struct refuses, is a door
    /// with an opinion of its own.
    #[test]
    fn test_hkdf_reports_output_too_long_where_the_struct_reports_it(
        ikm in prop::collection::vec(any::<u8>(), 0..64),
        past in 1_usize..64,
    ) {
        let wanted = MAX_OUTPUT_SIZE + past;

        let mut through_the_door = vec![0_u8; wanted];
        let mut through_the_struct = vec![0_u8; wanted];

        let door = hkdf(&[], &ikm, &[], &mut through_the_door);
        let derived = HkdfSha256::new().derive(&[], &ikm, &[], &mut through_the_struct);

        prop_assert_eq!(door, Err(HkdfError::OutputTooLong));
        prop_assert_eq!(door, derived);
    }
}
