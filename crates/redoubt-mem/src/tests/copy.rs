// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use crate::copy_nonoverlapping;

// ============================================================================
// copy_nonoverlapping
// ============================================================================

proptest! {
    #[test]
    fn test_copy_nonoverlapping_leaves_the_destination_equal_to_the_source(
        from in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut into: Vec<u8> = vec![0; from.len()];

        // SAFETY: two distinct allocations of the same length.
        unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };

        prop_assert_eq!(into, from);
    }
}
