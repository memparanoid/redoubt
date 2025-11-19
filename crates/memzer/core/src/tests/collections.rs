// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::{Zeroizable, ZeroizationProbe};

use super::utils::{is_zeroed_array, is_zeroed_slice, is_zeroed_vec};

const SIZE: usize = (u16::MAX / 4) as usize;

#[test]
fn test_vec() {
    let mut vec = Vec::<u8>::new();
    vec.resize_with(SIZE, || u8::MAX);

    assert!(!vec.is_zeroized());

    for i in 0..SIZE - 1 {
        vec[i].self_zeroize();
        assert!(!vec.is_zeroized());
    }

    vec.self_zeroize();

    assert!(vec.is_zeroized());
    assert!(is_zeroed_vec(&vec));
}

#[test]
fn test_array() {
    let mut array = [u8::MAX; SIZE];

    assert!(!array.is_zeroized());

    for i in 0..SIZE - 1 {
        array[i].self_zeroize();
        assert!(!array.is_zeroized());
    }

    array.self_zeroize();

    assert!(array.is_zeroized());
    assert!(is_zeroed_array(&array));
}

#[test]
fn test_slice() {
    let mut slice = [u8::MAX; SIZE];
    let slice = slice.as_mut_slice();

    assert!(!slice.is_zeroized());

    for i in 0..SIZE - 1 {
        slice[i].self_zeroize();
        assert!(!slice.is_zeroized());
    }

    slice.self_zeroize();

    assert!(slice.is_zeroized());
    assert!(is_zeroed_slice(slice));
}
