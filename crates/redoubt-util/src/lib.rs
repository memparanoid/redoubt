// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bulk zeroization of slices and vectors, the spare capacity included.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Parses a hexadecimal string into bytes.
///
/// The string must have an even number of characters and contain only
/// valid hexadecimal digits (0-9, a-f, A-F).
///
/// # Panics
///
/// Panics if the string contains invalid hex characters or has odd length.
///
/// # Example
///
/// ```
/// // Requires feature = "test-utils"
/// use redoubt_util::hex_to_bytes;
///
/// let bytes = hex_to_bytes("deadbeef");
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
/// ```
#[cfg(any(test, feature = "test-utils"))]
#[inline]
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Writes one value's own default over it, by a store the optimizer may not
/// remove.
///
/// For a primitive that default is its zero: `0` for the integers and the
/// floats, `false`, and `'\0'`. Asking the type for it rather than assembling
/// one out of zero bytes is what keeps a type whose zero is not a value — a
/// reference, a `NonZero` — from being written one.
///
/// # Example
///
/// ```
/// use redoubt_util::zeroize_primitive;
///
/// let mut x = 42u32;
/// zeroize_primitive(&mut x);
/// assert_eq!(x, 0);
///
/// let mut flag = true;
/// zeroize_primitive(&mut flag);
/// assert_eq!(flag, false);
///
/// let mut pi = 3.14f64;
/// zeroize_primitive(&mut pi);
/// assert_eq!(pi, 0.0);
/// ```
#[inline(always)]
pub fn zeroize_primitive<T: Default>(val: &mut T) {
    // SAFETY: `val` is a live, aligned `&mut T`, which is what a volatile
    // write needs. What is written is a `T` the type made itself, so no bit
    // pattern arrives that `T` does not have.
    unsafe {
        core::ptr::write_volatile(val, T::default());
    }
}

/// Writes zeros over every byte of the slice.
///
/// # Safety
///
/// Every byte zero has to be a value of `T`. It is not for a reference, a
/// `Box`, a `NonZero` or an enum with no variant at zero, and each element of
/// the slice is then a value `T` does not have.
///
/// # Example
///
/// ```
/// use redoubt_util::fast_zeroize_slice;
///
/// let mut data = vec![1u8, 2, 3, 4, 5];
/// // SAFETY: every byte zero is a `u8`.
/// unsafe { fast_zeroize_slice(&mut data) };
/// assert!(data.iter().all(|&b| b == 0));
///
/// let mut ints = vec![0xDEADBEEFu32; 10];
/// // SAFETY: every byte zero is a `u32`.
/// unsafe { fast_zeroize_slice(&mut ints) };
/// assert!(ints.iter().all(|&v| v == 0));
/// ```
#[inline(always)]
pub unsafe fn fast_zeroize_slice<T>(slice: &mut [T]) {
    // SAFETY: the count is the slice's own length, so the write stays inside
    // it, and `&mut [T]` is what makes it the only reference. That the zeros
    // are a `T` is the caller's.
    unsafe { redoubt_mem::zeroize(slice.as_mut_ptr(), slice.len()) };
}

/// Writes zeros over the whole allocation, the spare past `len` included.
///
/// # Safety
///
/// Every byte zero has to be a value of `T`. It is not for a reference, a
/// `Box`, a `NonZero` or an enum with no variant at zero, and each element the
/// `Vec` holds is then a value `T` does not have — dropped as one.
///
/// # Example
///
/// ```
/// use redoubt_util::fast_zeroize_vec;
///
/// let mut vec = vec![0xFFu8; 100];
/// vec.truncate(10);
///
/// // SAFETY: every byte zero is a `u8`.
/// unsafe { fast_zeroize_vec(&mut vec) };
/// assert!(vec.iter().all(|&b| b == 0));
/// ```
#[inline(always)]
pub unsafe fn fast_zeroize_vec<T>(vec: &mut Vec<T>) {
    // SAFETY: the count is the `Vec`'s own capacity, so the write stays inside
    // its allocation — the spare past `len` included, which is the point — and
    // `&mut Vec<T>` is what makes it the only reference. That the zeros are a
    // `T` is the caller's.
    unsafe { redoubt_mem::zeroize(vec.as_mut_ptr(), vec.capacity()) };
}

/// Writes zeros over the spare past `len`, and leaves the elements as they are.
///
/// # Example
///
/// ```
/// use redoubt_util::zeroize_spare_capacity;
///
/// let mut vec = vec![0xFFu8; 100];
/// vec.truncate(10);
///
/// zeroize_spare_capacity(&mut vec);
///
/// assert!(vec.iter().all(|&b| b == 0xFF));
/// ```
#[inline(always)]
pub fn zeroize_spare_capacity<T>(vec: &mut Vec<T>) {
    // SAFETY: `len` is inside the capacity, so offsetting by it lands in the
    // allocation, and what is written from there is the difference between the
    // two — the spare, and no element the `Vec` is holding. Nothing reads the
    // spare as a `T`, so the zeros need not be one.
    unsafe { redoubt_mem::zeroize(vec.as_mut_ptr().add(vec.len()), vec.capacity() - vec.len()) };
}
