// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt::Write;

use crate::traits::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};
use crate::zeroizing_mut_guard::ZeroizingMutGuard;

#[test]
fn test_guard_assert_zeroization_probe_trait() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    let mut guard = ZeroizingMutGuard::from(&mut vec);

    assert!(!guard.is_zeroized());
    guard.fast_zeroize();
    assert!(guard.is_zeroized());
}

#[test]
fn test_guard_assert_zeroed_on_drop_trait() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    let guard = ZeroizingMutGuard::from(&mut vec);

    guard.assert_zeroize_on_drop();
}

#[test]
fn test_guard_guared_trait() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    let mut guard = ZeroizingMutGuard::from(&mut vec);

    fn with_ref(vec: &[u8]) -> bool {
        vec.iter().sum::<u8>() == 15
    }

    fn with_mut(vec: &mut [u8]) -> bool {
        for item in vec.iter_mut() {
            *item *= 2
        }

        vec.iter().sum::<u8>() == 30
    }

    assert!(with_ref(&guard));
    assert!(with_mut(&mut guard));
}

#[test]
fn test_guard_debug() {
    let mut inner = vec![1u8, 2, 3];
    let guard = ZeroizingMutGuard::from(&mut inner);

    let mut buf = String::new();
    write!(&mut buf, "{:?}", guard).unwrap();
    assert_eq!(
        buf, "[REDACTED ZeroizingMutGuard]",
        "Debug should redact ZeroizingMutGuard"
    );
}
