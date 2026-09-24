// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::copy_nonoverlapping;

// ============================================================================
// copy_nonoverlapping
// ============================================================================

#[test]
fn test_copy_nonoverlapping_resolves_the_default_backend() {
    let from = [0x9E_u8, 0x41, 0x17, 0xC3];
    let mut into = [0_u8; 4];

    // SAFETY: two distinct arrays of the same length.
    unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };

    assert_eq!(into, from);
}
