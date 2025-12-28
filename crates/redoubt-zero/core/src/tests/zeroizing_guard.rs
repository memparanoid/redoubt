// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe, ZeroizingGuard};

#[test]
fn test_zeroizing_guard_from_default() {
    let guard: ZeroizingGuard<u64> = ZeroizingGuard::from_default();

    // Default value should be zeroized
    assert!(guard.is_zeroized());
    assert_eq!(*guard, 0);

    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_source_zeroized() {
    let mut value = 0xDEADBEEFu64;
    let guard = ZeroizingGuard::from_mut(&mut value);

    // Source must be zeroized
    assert_eq!(value, 0);
    assert!(value.is_zeroized());

    // Guard has the original value
    assert_eq!(*guard, 0xDEADBEEF);
}

#[test]
fn test_zeroizing_guard_with_array() {
    let mut arr = [0x42u8; 32];
    let guard = ZeroizingGuard::from_mut(&mut arr);

    // Source array should be zeroized
    assert!(arr.is_zeroized());

    // Guard has the original data
    assert!(guard.iter().all(|&b| b == 0x42));

    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_auto_zeroizes_on_drop() {
    let mut value = 42u64;
    let guard = ZeroizingGuard::from_mut(&mut value);

    // Source should be zeroized after from_mut
    assert!(value.is_zeroized());

    // Verify it auto-zeroizes when dropped
    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_manual_zeroize() {
    let mut value = 12345u64;
    let mut guard = ZeroizingGuard::from_mut(&mut value);

    // Initially not zeroized (inside guard)
    assert!(!guard.is_zeroized());

    // Manually zeroize
    guard.fast_zeroize();

    // Now it's zeroized
    assert!(guard.is_zeroized());
    assert_eq!(*guard, 0);
}

#[test]
fn test_zeroizing_guard_deref() {
    let mut value = 99u32;
    let guard = ZeroizingGuard::from_mut(&mut value);

    // Can read through Deref
    assert_eq!(*guard, 99);
}

#[test]
fn test_zeroizing_guard_deref_mut() {
    let mut value = 50u32;
    let mut guard = ZeroizingGuard::from_mut(&mut value);

    // Can mutate through DerefMut
    *guard = 100;
    assert_eq!(*guard, 100);
}

#[test]
fn test_zeroizing_guard_with_vec() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    let guard = ZeroizingGuard::from_mut(&mut vec);

    // Source vec should be empty (swapped with default)
    assert!(vec.is_empty());

    // Verify auto-zeroization
    guard.assert_zeroize_on_drop();
}

#[test]
fn test_zeroizing_guard_debug_redacts() {
    let mut value = 12345u64;
    let guard = ZeroizingGuard::from_mut(&mut value);
    let debug_str = format!("{:?}", guard);

    // Should not expose the value
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("12345"));
}
