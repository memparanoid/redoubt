// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for SensitiveArrayU8 and SensitiveArrayU32

use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

use crate::sensitive::{SensitiveArrayU32, SensitiveArrayU8};

macro_rules! test_sensitive_array {
    ($mod_name:ident, $type:ident, $zero:expr, $nonzero:expr) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn test_new_is_zeroed() {
                let arr = $type::<4>::new();
                assert!(arr.is_zeroed());
            }

            #[test]
            fn test_deref_read() {
                let mut arr = $type::<4>::new();
                arr[0] = $nonzero;
                arr[1] = $nonzero;

                assert_eq!(arr[0], $nonzero);
                assert_eq!(arr[1], $nonzero);
                assert_eq!(arr[2], $zero);
                arr.zeroize();
            }

            #[test]
            fn test_deref_mut_write() {
                let mut arr = $type::<4>::new();
                arr.copy_from_slice(&[$nonzero; 4]);
                assert_eq!(&arr[..], &[$nonzero; 4]);
                arr.zeroize();
            }

            #[test]
            fn test_zeroize_clears_data() {
                let mut arr = $type::<8>::new();
                arr.copy_from_slice(&[$nonzero; 8]);
                assert!(!arr.is_zeroed());
                arr.zeroize();
                assert!(arr.is_zeroed());
            }

            #[test]
            fn test_drop_without_zeroize_panics_in_debug() {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut arr = $type::<4>::new();
                    arr[0] = $nonzero;
                    // drop without zeroize
                }));

                #[cfg(debug_assertions)]
                assert!(
                    result.is_err(),
                    "Expected panic when dropping non-zeroed array"
                );

                #[cfg(not(debug_assertions))]
                assert!(result.is_ok());
            }

            #[test]
            fn test_drop_after_zeroize_ok() {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut arr = $type::<4>::new();
                    arr[0] = $nonzero;
                    arr.zeroize();
                }));

                assert!(result.is_ok(), "Should not panic when dropping zeroed array");
            }
        }
    };
}

test_sensitive_array!(u8_tests, SensitiveArrayU8, 0u8, 0xFFu8);
test_sensitive_array!(u32_tests, SensitiveArrayU32, 0u32, 0xDEAD_BEEFu32);

#[test]
fn test_drain_le() {
    let mut arr = SensitiveArrayU32::<4>::new();
    arr[0] = 0xDEAD_BEEF;
    arr[1] = 0x1234_5678;

    let mut dst = [0u8; 4];

    arr.drain_le(0, &mut dst);
    // Little-endian: 0xDEADBEEF -> [0xEF, 0xBE, 0xAD, 0xDE]
    assert_eq!(dst, [0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(arr[0], 0); // zeroized

    arr.drain_le(1, &mut dst);
    assert_eq!(dst, [0x78, 0x56, 0x34, 0x12]);
    assert_eq!(arr[1], 0);

    arr.zeroize();
}
