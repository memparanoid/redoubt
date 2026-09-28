// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec::Vec;

use proptest::prelude::*;

use crate::zeroize;

// ============================================================================
// zeroize
// ============================================================================

proptest! {
    #[test]
    fn test_zeroize_leaves_every_byte_zero(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut held: Vec<u8> = bytes;

        // SAFETY: the vec is writable for its own length, and every byte zero
        // is a `u8`.
        unsafe { zeroize(held.as_mut_ptr(), held.len()) };

        prop_assert!(held.iter().all(|byte| *byte == 0));
    }
}
