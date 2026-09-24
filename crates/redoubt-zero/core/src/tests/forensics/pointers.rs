// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ============================================================================
// *mut T::is_zeroized
// ============================================================================

#[test]
#[ignore = "Reads no secret: it compares an address with null."]
fn test_probing_a_mutable_pointer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// *mut T::fast_zeroize
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes null over an address."]
fn test_zeroizing_a_mutable_pointer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// *const T::is_zeroized
// ============================================================================

#[test]
#[ignore = "Reads no secret: it compares an address with null."]
fn test_probing_a_constant_pointer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// *const T::fast_zeroize
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes null over an address."]
fn test_zeroizing_a_constant_pointer_leaves_nothing() {
    // Intentionally empty.
}
