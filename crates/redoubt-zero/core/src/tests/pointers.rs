// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ptr;

use crate::traits::{FastZeroizable, ZeroizationProbe};

macro_rules! test_ptr_zeroization {
    ($($ty:ty),* $(,)?) => {
        $(
            // *mut $ty
            {
                let mut value: $ty = unsafe { core::mem::zeroed() };
                let mut ptr: *mut $ty = &mut value;

                assert!(!ptr.is_zeroized(), concat!("non-null *mut ", stringify!($ty), " should not be zeroized"));

                ptr.fast_zeroize();

                assert!(ptr.is_zeroized(), concat!("*mut ", stringify!($ty), " should be zeroized after fast_zeroize"));
                assert!(ptr.is_null(), concat!("*mut ", stringify!($ty), " should be null after fast_zeroize"));
            }

            // *const $ty
            {
                let value: $ty = unsafe { core::mem::zeroed() };
                let mut ptr: *const $ty = &value;

                assert!(!ptr.is_zeroized(), concat!("non-null *const ", stringify!($ty), " should not be zeroized"));

                ptr.fast_zeroize();

                assert!(ptr.is_zeroized(), concat!("*const ", stringify!($ty), " should be zeroized after fast_zeroize"));
                assert!(ptr.is_null(), concat!("*const ", stringify!($ty), " should be null after fast_zeroize"));
            }
        )*
    };
}

#[test]
fn test_ptr_zeroization_all_types() {
    test_ptr_zeroization!(
        u8, u16, u32, u64, u128, usize,
        i8, i16, i32, i64, i128, isize,
        f32, f64, bool, char,
    );
}

#[test]
fn test_null_ptrs_are_zeroized() {
    let ptr_mut: *mut u8 = ptr::null_mut();
    let ptr_const: *const u8 = ptr::null();

    assert!(ptr_mut.is_zeroized(), "null *mut should be zeroized");
    assert!(ptr_const.is_zeroized(), "null *const should be zeroized");
}
