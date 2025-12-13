// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::collections::{slice_fast_zeroize, vec_fast_zeroize};
use crate::traits::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

const SIZE: usize = (u16::MAX / 4) as usize;

// === === === === === === === === === ===
// Test helpers
// === === === === === === === === === ===

// Test type with CAN_BE_BULK_ZEROIZED = false
#[derive(Clone)]
struct ComplexType {
    data: u64,
}

impl ComplexType {
    fn new(data: u64) -> Self {
        Self { data }
    }
}

impl ZeroizeMetadata for ComplexType {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for ComplexType {
    fn fast_zeroize(&mut self) {
        self.data = 0;
    }
}

impl ZeroizationProbe for ComplexType {
    fn is_zeroized(&self) -> bool {
        self.data == 0
    }
}

// === === === === === === === === === ===
// [T] - slices
// === === === === === === === === === ===

#[test]
fn test_slice() {
    let mut slice = [u8::MAX; SIZE];
    let slice = slice.as_mut_slice();

    assert!(!slice.is_zeroized());

    for i in 0..SIZE - 1 {
        slice[i].fast_zeroize();
        assert!(!slice.is_zeroized());
    }

    slice.fast_zeroize();

    assert!(slice.is_zeroized());
    assert!(redoubt_util::is_slice_zeroized(slice));
}

#[test]
fn test_slice_fast_zeroize_fast_true() {
    // NOTE: fast=true forces memset of entire array, regardless of T::CAN_BE_BULK_ZEROIZED.
    // This is only safe for types where all-zeros is a valid bit pattern.
    // ComplexType happens to be safe (all fields are primitives/Copy), but this
    // test may break if ComplexType's layout changes.
    let mut arr = [
        ComplexType::new(100),
        ComplexType::new(200),
        ComplexType::new(300),
    ];

    assert!(!arr.is_zeroized());

    slice_fast_zeroize(arr.as_mut_slice(), true);

    // Assert zeroization!
    assert!(arr.is_zeroized());
}

#[test]
fn test_slice_fast_zeroize_fast_false() {
    // Test fast=false path: recursive zeroization
    let mut arr = [
        ComplexType::new(100),
        ComplexType::new(200),
        ComplexType::new(300),
    ];

    assert!(!arr.is_zeroized());

    slice_fast_zeroize(&mut arr, false);

    // Assert zeroization!
    assert!(arr.is_zeroized());
}

// === === === === === === === === === ===
// [T; N] - arrays
// === === === === === === === === === ===

#[test]
fn test_array() {
    let mut array = [u8::MAX; SIZE];

    assert!(!array.is_zeroized());

    for i in 0..SIZE - 1 {
        array[i].fast_zeroize();
        assert!(!array.is_zeroized());
    }

    array.fast_zeroize();

    assert!(array.is_zeroized());
    assert!(redoubt_util::is_slice_zeroized(&array));
}

// === === === === === === === === === ===
// Vec<T>
// === === === === === === === === === ===

#[test]
fn test_vec() {
    let mut vec = Vec::<u8>::new();
    vec.resize_with(SIZE, || u8::MAX);

    assert!(!vec.is_zeroized());

    for i in 0..SIZE - 1 {
        vec[i].fast_zeroize();
        assert!(!vec.is_zeroized());
    }

    vec.fast_zeroize();

    // Assert zeroization!
    assert!(vec.is_zeroized());
    assert!(redoubt_util::is_vec_fully_zeroized(&vec));
}

#[test]
fn test_vec_fast_zeroize_fast_true() {
    // NOTE: fast=true forces memset of entire vec, regardless of T::CAN_BE_BULK_ZEROIZED.
    // This is only safe for types where all-zeros is a valid bit pattern.
    // ComplexType happens to be safe (all fields are primitives/Copy), but this
    // test may break if ComplexType's layout changes.
    let mut vec = vec![
        ComplexType::new(100),
        ComplexType::new(200),
        ComplexType::new(300),
    ];
    vec.reserve(10); // Add spare capacity

    assert!(!vec.is_zeroized());

    vec_fast_zeroize(&mut vec, true);

    // Assert zeroization!
    assert!(vec.is_zeroized());
}

#[test]
fn test_vec_fast_zeroize_fast_false() {
    // Test fast=false path: recursive zeroization + spare capacity
    let mut vec = vec![
        ComplexType::new(100),
        ComplexType::new(200),
        ComplexType::new(300),
    ];
    vec.reserve(10); // Add spare capacity

    assert!(!vec.is_zeroized());

    vec_fast_zeroize(&mut vec, false);

    // Assert zeroization!
    assert!(vec.is_zeroized());
}

#[test]
fn test_vec_spare_capacity_recursive_zeroize() {
    // Test that Vec<Vec<ComplexType>> properly zeroizes:
    // - Inner Vec elements (ComplexType values)
    // - Outer Vec elements (inner Vec structures)
    // - Spare capacity at both levels
    let mut vec = vec![
        vec![ComplexType::new(100)],
        vec![ComplexType::new(200), ComplexType::new(300)],
        vec![
            ComplexType::new(400),
            ComplexType::new(500),
            ComplexType::new(600),
        ],
    ];

    // Not zeroized initially
    assert!(!vec.is_zeroized());

    vec.fast_zeroize();

    // After fast_zeroize, all elements and spare capacity should be zeroed
    assert!(vec.is_zeroized());
}

// === === === === === === === === === ===
// String
// === === === === === === === === === ===

#[test]
fn test_string() {
    let mut s = "A".repeat(SIZE);

    assert!(!s.is_zeroized());

    s.fast_zeroize();

    assert!(s.is_zeroized());
    assert!(redoubt_util::is_slice_zeroized(s.as_bytes()));
}
