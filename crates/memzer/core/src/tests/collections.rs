// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::{Zeroizable, ZeroizationProbe};

const SIZE: usize = (u16::MAX / 4) as usize;

#[test]
fn test_string() {
    let mut s = "A".repeat(SIZE);

    assert!(!s.is_zeroized());

    s.self_zeroize();

    assert!(s.is_zeroized());
    assert!(memutil::is_slice_zeroized(s.as_bytes()));
}

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
    assert!(memutil::is_vec_fully_zeroized(&vec));
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
    assert!(memutil::is_slice_zeroized(&array));
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
    assert!(memutil::is_slice_zeroized(slice));
}
