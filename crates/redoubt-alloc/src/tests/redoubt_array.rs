// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::RedoubtArray;
use redoubt_zero::ZeroizationProbe;

// =============================================================================
// new()
// =============================================================================

#[test]
fn test_new() {
    let arr: RedoubtArray<u8, 32> = RedoubtArray::new();

    assert_eq!(arr.len(), 32);
    assert!(!arr.is_empty());
}

// =============================================================================
// from_mut_array()
// =============================================================================

#[test]
fn test_from_mut_array() {
    let mut data = [1u8, 2, 3, 4, 5];
    let arr = RedoubtArray::from_mut_array(&mut data);

    assert_eq!(arr.as_slice(), [1, 2, 3, 4, 5]);
    assert!(data.is_zeroized());
}

// =============================================================================
// len(), is_empty()
// =============================================================================

#[test]
fn test_len_and_is_empty() {
    let arr: RedoubtArray<u8, 32> = RedoubtArray::new();

    assert_eq!(arr.len(), 32);
    assert!(!arr.is_empty());

    let empty: RedoubtArray<u8, 0> = RedoubtArray::new();

    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

// =============================================================================
// replace_from_mut_array()
// =============================================================================

#[test]
fn test_replace_from_mut_array() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [42u8; 32];

    arr.replace_from_mut_array(&mut src);

    // Verify data was copied
    assert_eq!(arr.as_slice(), &[42u8; 32]);

    // Verify source was zeroized
    assert!(src.is_zeroized());
}

#[test]
fn test_replace_from_mut_array_replaces_existing() {
    let mut arr = RedoubtArray::<u8, 32>::new();

    // First replacement
    let mut src1 = [1u8; 32];
    arr.replace_from_mut_array(&mut src1);
    assert_eq!(arr[0], 1);
    assert!(src1.is_zeroized());

    // Second replacement
    let mut src2 = [2u8; 32];
    arr.replace_from_mut_array(&mut src2);
    assert_eq!(arr[0], 2);
    assert!(src2.is_zeroized());
}

#[test]
fn test_replace_from_mut_array_pattern() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [0u8; 32];
    for (i, item) in src.iter_mut().enumerate() {
        *item = i as u8;
    }

    arr.replace_from_mut_array(&mut src);

    // Verify pattern
    for i in 0..32 {
        assert_eq!(arr[i], i as u8);
    }

    // Source zeroized
    assert!(src.is_zeroized());
}

// =============================================================================
// as_slice()
// =============================================================================

#[test]
fn test_as_slice() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [7u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let slice = arr.as_slice();

    assert_eq!(slice.len(), 32);
    assert_eq!(slice[0], 7);
}

// =============================================================================
// as_mut_slice()
// =============================================================================

#[test]
fn test_as_mut_slice() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [1u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let slice_mut = arr.as_mut_slice();
    slice_mut[0] = 99;

    assert_eq!(arr[0], 99);
}

// =============================================================================
// as_array()
// =============================================================================

#[test]
fn test_as_array() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [7u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let array_ref: &[u8; 32] = arr.as_array();

    assert_eq!(array_ref.len(), 32);
    assert_eq!(array_ref[0], 7);
}

#[test]
fn test_as_array_pattern_matching() {
    let mut arr = RedoubtArray::<u8, 3>::new();
    let mut src = [10u8, 20u8, 30u8];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let [a, b, c] = *arr.as_array();

    assert_eq!(a, 10);
    assert_eq!(b, 20);
    assert_eq!(c, 30);
}

// =============================================================================
// as_mut_array()
// =============================================================================

#[test]
fn test_as_mut_array() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [1u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let array_mut_ref = arr.as_mut_array();
    array_mut_ref[0] = 99;
    array_mut_ref[31] = 88;

    assert_eq!(arr[0], 99);
    assert_eq!(arr[31], 88);
}

#[test]
fn test_as_mut_array_full_replacement() {
    let mut arr = RedoubtArray::<u8, 4>::new();
    let mut src = [1u8, 2u8, 3u8, 4u8];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let array_mut_ref = arr.as_mut_array();
    *array_mut_ref = [10u8, 20u8, 30u8, 40u8];

    assert_eq!(arr[0], 10);
    assert_eq!(arr[1], 20);
    assert_eq!(arr[2], 30);
    assert_eq!(arr[3], 40);
}

// =============================================================================
// Default
// =============================================================================

#[test]
fn test_default() {
    let arr: RedoubtArray<u8, 32> = RedoubtArray::default();

    assert_eq!(arr.len(), 32);
    assert!(!arr.is_empty());
}

// =============================================================================
// PartialEq / Eq
// =============================================================================

#[test]
fn test_partial_eq_equal_arrays() {
    let mut arr1 = RedoubtArray::<u8, 32>::new();
    let mut src1 = [5u8; 32];

    arr1.replace_from_mut_array(&mut src1);
    assert!(src1.is_zeroized());

    let mut arr2 = RedoubtArray::<u8, 32>::new();
    let mut src2 = [5u8; 32];

    arr2.replace_from_mut_array(&mut src2);
    assert!(src2.is_zeroized());

    assert_eq!(arr1.as_slice(), arr2.as_slice());
    assert!(arr1 == arr2);
}

#[test]
fn test_partial_eq_different_arrays() {
    let mut arr1 = RedoubtArray::<u8, 32>::new();
    let mut src1 = [1u8; 32];

    arr1.replace_from_mut_array(&mut src1);
    assert!(src1.is_zeroized());

    let mut arr2 = RedoubtArray::<u8, 32>::new();
    let mut src2 = [2u8; 32];

    arr2.replace_from_mut_array(&mut src2);
    assert!(src2.is_zeroized());

    assert_ne!(arr1.as_slice(), arr2.as_slice());
    assert!(arr1 != arr2);
}

// =============================================================================
// Deref / DerefMut
// =============================================================================

#[test]
fn test_deref() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [42u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    // Deref to slice
    let slice: &[u8] = &arr;
    assert_eq!(slice, &[42u8; 32]);

    // DerefMut to slice
    let slice_mut: &mut [u8] = &mut arr;
    slice_mut[0] = 99;

    assert_eq!(arr[0], 99);
}

// =============================================================================
// Debug
// =============================================================================

#[test]
fn test_debug_redacted() {
    let mut arr = RedoubtArray::<u8, 32>::new();
    let mut src = [42u8; 32];

    arr.replace_from_mut_array(&mut src);
    assert!(src.is_zeroized());

    let debug_output = format!("{:?}", arr);

    assert!(debug_output.contains("RedoubtArray"));
    assert!(debug_output.contains("REDACTED"));
    assert!(debug_output.contains("len"));
    // Verify actual data values are not in the output
    assert!(!debug_output.contains("42"));
}
