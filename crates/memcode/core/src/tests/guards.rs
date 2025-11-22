// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::guards::{BytesGuard, PrimitiveGuard};

#[test]
fn test_primitive_guard() {
    macro_rules! test_guard_for {
        ($ty:ty) => {{
            let mut value = <$ty>::MAX;

            fn with_guard_ref(v: &$ty) -> bool {
                *v == <$ty>::MAX
            }

            let guard = PrimitiveGuard::from(&mut value);
            assert!(with_guard_ref(guard.as_ref()));
            drop(guard);

            // Assert zeroization!
            assert_eq!(value, 0);
        }};
    }

    test_guard_for!(u8);
    test_guard_for!(u16);
    test_guard_for!(u32);
    test_guard_for!(u64);
}

#[test]
fn test_bytes_guard() {
    let mut bytes = [0, 1, 2, 3, 4, 5];

    fn with_guard_ref(bytes: &[u8]) -> bool {
        bytes == &[0, 1, 2, 3, 4, 5]
    }

    fn with_guard_mut(bytes: &mut [u8]) -> bool {
        for item in bytes.iter_mut() {
            *item *= 2;
        }

        bytes == &[0, 2, 4, 6, 8, 10]
    }

    let mut guard = BytesGuard::from(&mut bytes);

    assert!(with_guard_ref(guard.as_ref()));
    assert!(with_guard_mut(guard.as_mut()));

    drop(guard);

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
}
