// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec;

use proptest::prelude::*;

use crate::is_zeroized;

// ============================================================================
// is_zeroized
// ============================================================================

proptest! {
    #[test]
    fn test_is_zeroized_returns_true_for_zeros_of_any_length(len in 0_usize..1024) {
        prop_assert!(is_zeroized(&vec![0_u8; len]));
    }

    #[test]
    fn test_is_zeroized_returns_false_for_zeros_holding_any_byte_that_is_not(
        len in 1_usize..1024,
        at in any::<prop::sample::Index>(),
        byte in 1_u8..=u8::MAX,
    ) {
        let mut bytes = vec![0_u8; len];

        bytes[at.index(len)] = byte;

        prop_assert!(!is_zeroized(&bytes));
    }
}
