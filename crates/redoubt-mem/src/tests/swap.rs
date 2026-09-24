// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec::Vec;

use proptest::prelude::*;

use crate::{swap, swap_nonoverlapping};

// ============================================================================
// swap
// ============================================================================

proptest! {
    #[test]
    fn test_swap_exchanges_the_two_values(first in any::<[u64; 4]>(), second in any::<[u64; 4]>()) {
        let mut a = first;
        let mut b = second;

        swap(&mut a, &mut b);

        prop_assert_eq!((a, b), (second, first));
    }
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

proptest! {
    #[test]
    fn test_swap_nonoverlapping_exchanges_the_two_ranges(
        pairs in proptest::collection::vec(any::<(u8, u8)>(), 0..1024),
    ) {
        let (first, second): (Vec<u8>, Vec<u8>) = pairs.into_iter().unzip();
        let mut a = first.clone();
        let mut b = second.clone();

        // SAFETY: two distinct allocations of the same length.
        unsafe { swap_nonoverlapping(a.as_mut_ptr(), b.as_mut_ptr(), a.len()) };

        prop_assert_eq!((a, b), (second, first));
    }
}
