// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe, ZeroizingGuard};

#[test]
fn test_zeroizing_guard_auto_zeroizes_on_drop() {
    // Create a guard with a value
    let guard = ZeroizingGuard::new(42u64);

    // Verify it auto-zeroizes when dropped
    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_manual_zeroize() {
    let mut guard = ZeroizingGuard::new(12345u64);

    // Initially not zeroized
    assert!(!guard.is_zeroized());

    // Manually zeroize
    guard.fast_zeroize();

    // Now it's zeroized
    assert!(guard.is_zeroized());
    assert_eq!(*guard, 0);
}

#[test]
fn test_zeroizing_guard_deref() {
    let guard = ZeroizingGuard::new(99u32);

    // Can read through Deref
    assert_eq!(*guard, 99);
}

#[test]
fn test_zeroizing_guard_deref_mut() {
    let mut guard = ZeroizingGuard::new(50u32);

    // Can mutate through DerefMut
    *guard = 100;
    assert_eq!(*guard, 100);
}

#[test]
fn test_zeroizing_guard_with_vec() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let guard = ZeroizingGuard::new(vec);

    // Verify auto-zeroization
    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_into_inner() {
    let guard = ZeroizingGuard::new(42u64);
    let mut value = guard.into_inner();

    // Value is NOT zeroized yet - caller must do it
    assert_eq!(value, 42);

    // Caller manually zeroizes
    value.fast_zeroize();
    assert!(value.is_zeroized());
}

#[test]
fn test_zeroizing_guard_debug_redacts() {
    let guard = ZeroizingGuard::new(12345u64);
    let debug_str = format!("{:?}", guard);

    // Should not expose the value
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("12345"));
}
