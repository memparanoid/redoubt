// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The check both backends make, asked once rather than through each of them.

use std::panic::catch_unwind;

use redoubt_aead_core::consts::chacha::{BLOCK_SIZE, NONCE_SIZE};

use crate::backend::helpers::{check_counter, last_counter};

// === === === === === === === === === ===
// last_counter
// === === === === === === === === === ===

#[test]
fn test_last_counter_returns_the_rfc_ceiling_for_twelve_bytes() {
    assert_eq!(last_counter(NONCE_SIZE), u64::from(u32::MAX));
}

#[test]
fn test_last_counter_returns_the_bernstein_ceiling_for_eight_bytes() {
    assert_eq!(last_counter(8), u64::MAX);
}

// === === === === === === === === === ===
// check_counter
// === === === === === === === === === ===

#[test]
fn test_check_counter_rejects_a_counter_past_the_ceiling() {
    let result = catch_unwind(|| check_counter(u64::from(u32::MAX) + 1, u64::from(u32::MAX), 0));

    assert!(result.is_err());
}

/// The block the counter is already on is the one it may still write, so what
/// decides is how many come after it.
#[test]
fn test_check_counter_rejects_a_message_that_outruns_what_is_left() {
    for blocks in 2..=5_u64 {
        let last = u64::from(u32::MAX);
        let counter = last - blocks + 2;

        let result =
            catch_unwind(move || check_counter(counter, last, blocks as usize * BLOCK_SIZE));

        assert!(result.is_err(), "{blocks} blocks from {counter}");
    }
}

#[test]
fn test_check_counter_accepts_a_message_that_ends_on_the_ceiling() {
    for blocks in 1..=5_u64 {
        let last = u64::from(u32::MAX);

        check_counter(last - blocks + 1, last, blocks as usize * BLOCK_SIZE);
    }
}

/// Nothing to write is nothing to run out of, so the ceiling itself is allowed.
#[test]
fn test_check_counter_accepts_an_empty_message_on_the_ceiling() {
    check_counter(u64::MAX, u64::MAX, 0);
}
