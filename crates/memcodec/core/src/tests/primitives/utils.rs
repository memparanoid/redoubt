// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::traits::{BytesRequired, Decode, Encode};

/// Generates n equidistant values in [0, MAX] for unsigned types
pub(crate) fn equidistant_unsigned<T>(n: usize) -> Vec<T>
where
    T: Copy
        + From<u8>
        + TryFrom<u128>
        + core::ops::Add<Output = T>
        + core::ops::Div<Output = T>
        + core::ops::Mul<Output = T>,
    u128: From<T>,
{
    let max: u128 = u128::from(T::try_from(u128::MAX).unwrap_or_else(|_| {
        // T is smaller than u128, get its max
        T::try_from((1u128 << (core::mem::size_of::<T>() * 8)) - 1).unwrap_or_else(|_| T::from(0))
    }));

    // Actually get T::MAX properly
    let t_max = if core::mem::size_of::<T>() >= 16 {
        u128::MAX
    } else {
        (1u128 << (core::mem::size_of::<T>() * 8)) - 1
    };

    let step = t_max / (n as u128 - 1);
    let mut result = Vec::with_capacity(n);

    for i in 0..n {
        let val = (i as u128) * step;
        let val = val.min(t_max);
        if let Ok(v) = T::try_from(val) {
            result.push(v);
        }
    }

    result
}

/// Generates n equidistant values in [MIN, MAX] for signed types
pub(crate) fn equidistant_signed<T>(n: usize) -> Vec<T>
where
    T: Copy + TryFrom<i128>,
    i128: From<T>,
{
    let t_min: i128 = if core::mem::size_of::<T>() >= 16 {
        i128::MIN
    } else {
        -(1i128 << (core::mem::size_of::<T>() * 8 - 1))
    };

    let t_max: i128 = if core::mem::size_of::<T>() >= 16 {
        i128::MAX
    } else {
        (1i128 << (core::mem::size_of::<T>() * 8 - 1)) - 1
    };

    let range = (t_max as i128).wrapping_sub(t_min as i128) as u128;
    let step = range / (n as u128 - 1);
    let mut result = Vec::with_capacity(n);

    for i in 0..n {
        let val = (t_min as i128).wrapping_add((i as u128 * step) as i128);
        if let Ok(v) = T::try_from(val) {
            result.push(v);
        }
    }

    result
}

/// Tests encode(original) -> decode into recovered -> assert using custom comparator
pub(crate) fn test_roundtrip_with<T, F>(original_value: T, initial_recovered: T, compare: F)
where
    T: Encode + Decode + BytesRequired + Clone,
    F: Fn(&T, &T) -> bool,
{
    let mut original = original_value.clone();

    let mut buf = Buffer::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    original
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = initial_recovered;
    recovered
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert!(compare(&recovered, &original_value));
}

/// For each pair (T_0, T_1) from the set, runs the 4 combinations with custom comparator
pub(crate) fn test_all_pairs_with<T, F>(set: &[T], compare: F)
where
    T: Encode + Decode + BytesRequired + Clone,
    F: Fn(&T, &T) -> bool,
{
    for i in 0..set.len() {
        for j in i..set.len() {
            let t0 = set[i].clone();
            let t1 = set[j].clone();

            test_roundtrip_with(t0.clone(), t0.clone(), &compare);
            test_roundtrip_with(t0.clone(), t1.clone(), &compare);
            test_roundtrip_with(t1.clone(), t0.clone(), &compare);
            test_roundtrip_with(t1.clone(), t1.clone(), &compare);
        }
    }
}

/// For each pair using PartialEq (convenience wrapper)
pub(crate) fn test_all_pairs<T>(set: &[T])
where
    T: Encode + Decode + BytesRequired + Clone + PartialEq,
{
    test_all_pairs_with(set, |a, b| a == b);
}
