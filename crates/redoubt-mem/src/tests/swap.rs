// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{swap, swap_nonoverlapping};

// ============================================================================
// swap
// ============================================================================

#[test]
fn test_swap_resolves_the_default_backend() {
    let mut a = [0x9E_u8; 32];
    let mut b = [0x41_u8; 32];

    swap(&mut a, &mut b);

    assert_eq!((a, b), ([0x41; 32], [0x9E; 32]));
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

#[test]
fn test_swap_nonoverlapping_resolves_the_default_backend() {
    let mut a = [0x9E_u8; 32];
    let mut b = [0x41_u8; 32];

    // SAFETY: two distinct arrays of the same length.
    unsafe { swap_nonoverlapping(a.as_mut_ptr(), b.as_mut_ptr(), a.len()) };

    assert_eq!((a, b), ([0x41; 32], [0x9E; 32]));
}
