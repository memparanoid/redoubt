// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memory utilities for secure byte conversions and verification.
//!
//! All conversion functions zeroize source data after reading to prevent
//! sensitive data from lingering on the stack.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// Fills a byte slice with a repeating pattern byte.
///
/// This is useful for initializing memory buffers with a known value,
/// such as zeroing out sensitive data or filling with a sentinel pattern.
///
/// # Example
///
/// ```
/// use memutil::fill_bytes_with_pattern;
///
/// let mut buffer = [0u8; 8];
/// fill_bytes_with_pattern(&mut buffer, 0xAB);
/// assert!(buffer.iter().all(|&b| b == 0xAB));
///
/// // Zero out the buffer
/// fill_bytes_with_pattern(&mut buffer, 0);
/// assert!(buffer.iter().all(|&b| b == 0));
/// ```
#[inline]
pub fn fill_bytes_with_pattern(slice: &mut [u8], pattern: u8) {
    for byte in slice.iter_mut() {
        *byte = pattern;
    }
}

/// Constant-time equality comparison for byte slices.
///
/// Returns `true` if slices are equal, `false` otherwise.
/// The comparison time is constant regardless of where differences occur,
/// preventing timing side-channel attacks.
///
/// # Example
///
/// ```
/// use memutil::constant_time_eq;
///
/// let a = [1, 2, 3, 4];
/// let b = [1, 2, 3, 4];
/// let c = [1, 2, 3, 5];
///
/// assert!(constant_time_eq(&a, &b));
/// assert!(!constant_time_eq(&a, &c));
/// ```
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

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
/// use memutil::hex_to_bytes;
///
/// let bytes = hex_to_bytes("deadbeef");
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
/// ```
#[inline]
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Generates `{type}_from_le` and `{type}_to_le` functions for integer types.
macro_rules! impl_le_conversions {
    ($type:ty, $size:expr, $fn_from:ident, $fn_to:ident) => {
        #[doc = concat!("Converts ", stringify!($size), " bytes to a little-endian `", stringify!($type), "`, zeroizing the source bytes.")]
        ///
        /// This function avoids creating temporary byte arrays that could
        /// leak sensitive data on the stack. Instead, it builds the integer using
        /// bit shifts and zeroizes each source byte after reading.
        #[inline(always)]
        pub fn $fn_from(dst: &mut $type, bytes: &mut [u8; $size]) {
            *dst = 0;
            for (i, byte) in bytes.iter_mut().enumerate() {
                *dst |= (*byte as $type) << (8 * i);
                *byte = 0;
            }
        }

        #[doc = concat!("Converts a `", stringify!($type), "` to little-endian bytes, zeroizing the source.")]
        ///
        /// This function avoids creating temporary byte arrays that could
        /// leak sensitive data on the stack. Instead, it extracts bytes using
        /// bit shifts and zeroizes the source integer after writing.
        #[inline(always)]
        pub fn $fn_to(src: &mut $type, bytes: &mut [u8; $size]) {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (*src >> (8 * i)) as u8;
            }
            *src = 0;
        }
    };
}

impl_le_conversions!(u16, 2, u16_from_le, u16_to_le);
impl_le_conversions!(u32, 4, u32_from_le, u32_to_le);
impl_le_conversions!(u64, 8, u64_from_le, u64_to_le);

// usize: platform-dependent size
#[cfg(target_pointer_width = "32")]
impl_le_conversions!(usize, 4, usize_from_le, usize_to_le);
#[cfg(target_pointer_width = "64")]
impl_le_conversions!(usize, 8, usize_from_le, usize_to_le);

/// Verifies that a slice is zeroized.
///
/// Checks that all bytes in the slice are zero.
///
/// # Example
///
/// ```
/// use memutil::is_slice_zeroized;
///
/// let zeroed = [0u8; 10];
/// assert!(is_slice_zeroized(&zeroed));
///
/// let not_zeroed = [0u8, 1, 0, 0];
/// assert!(!is_slice_zeroized(&not_zeroed));
/// ```
#[inline(always)]
pub fn is_slice_zeroized(slice: &[u8]) -> bool {
    slice.iter().all(|&b| b == 0)
}

/// Verifies that a `Vec<u8>` is fully zeroized, including spare capacity.
///
/// This function checks **the entire allocation** (from index 0 to capacity),
/// not just the active elements (0 to len). This is critical for detecting
/// potential data leaks in spare capacity after operations like `truncate()`.
///
/// # Safety
///
/// This function uses `unsafe` to read spare capacity memory (region between
/// `len()` and `capacity()`). The implementation is sound because:
/// - `Vec` guarantees the allocation is valid for `capacity` bytes
/// - We only read, never write
/// - All indices are bounds-checked against `capacity`
///
/// # Example
///
/// ```
/// use memutil::{fast_zeroize_vec, is_vec_fully_zeroized};
///
/// let mut vec = vec![1u8, 2, 3, 4, 5];
/// vec.truncate(2); // len = 2, capacity = 5
///
/// // Manually zero the active elements (len = 2)
/// for byte in vec.iter_mut() {
///     *byte = 0;
/// }
///
/// // Spare capacity [2..5] still contains old data
/// assert!(!is_vec_fully_zeroized(&vec));
///
/// // fast_zeroize_vec clears BOTH active elements AND spare capacity
/// fast_zeroize_vec(&mut vec);
/// assert!(is_vec_fully_zeroized(&vec));
/// ```
#[inline(never)]
pub fn is_vec_fully_zeroized(vec: &Vec<u8>) -> bool {
    let cap = vec.capacity();
    let base = vec.as_ptr();

    for i in 0..cap {
        unsafe {
            if *base.add(i) != 0 {
                return false;
            }
        }
    }

    true
}

/// Zeroizes a single primitive value using volatile write.
///
/// Works for all primitive types where all-zeros is a valid representation:
/// - Integers (u8-u128, i8-i128, usize, isize): zeroed to 0
/// - Bool: zeroed to `false`
/// - Floats (f32, f64): zeroed to 0.0
/// - Char: zeroed to null character '\0'
///
/// # Safety
///
/// This function is safe because it uses `mem::zeroed()` which is valid
/// for all primitive types. The volatile write ensures the compiler cannot
/// optimize away the zeroization.
///
/// # Example
///
/// ```
/// use memutil::zeroize_primitive;
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
pub fn zeroize_primitive<T>(val: &mut T) {
    unsafe {
        core::ptr::write_volatile(val, core::mem::zeroed());
    }
}

/// Fast bulk zeroization that can be vectorized.
///
/// Uses `write_bytes` (memset) + volatile read to prevent the optimizer
/// from removing the zeroization. This is ~20x faster than byte-by-byte
/// volatile writes used by the `zeroize` crate.
///
/// Works with any type `T` by treating the slice as raw bytes.
///
/// # Example
///
/// ```
/// use memutil::fast_zeroize_slice;
///
/// let mut data = vec![1u8, 2, 3, 4, 5];
/// fast_zeroize_slice(&mut data);
/// assert!(data.iter().all(|&b| b == 0));
///
/// let mut ints = vec![0xDEADBEEFu32; 10];
/// fast_zeroize_slice(&mut ints);
/// assert!(ints.iter().all(|&v| v == 0));
/// ```
#[inline(always)]
pub fn fast_zeroize_slice<T>(slice: &mut [T]) {
    if slice.is_empty() {
        return;
    }

    let byte_len = core::mem::size_of_val(slice);
    unsafe {
        core::ptr::write_bytes(slice.as_mut_ptr() as *mut u8, 0, byte_len);
        // Volatile read prevents the optimizer from removing the write_bytes
        core::ptr::read_volatile(slice.as_ptr() as *const u8);
    }
}

/// Fast bulk zeroization of a Vec including spare capacity.
///
/// Zeroizes the **entire allocation** (from index 0 to capacity),
/// not just the active elements (0 to len). This ensures no sensitive
/// data remains in spare capacity after operations like `truncate()`.
///
/// Uses `write_bytes` (memset) + volatile read, same as `fast_zeroize_slice`.
///
/// # Example
///
/// ```
/// use memutil::{fast_zeroize_vec, is_vec_fully_zeroized};
///
/// let mut vec = vec![0xFFu8; 100];
/// vec.truncate(10);  // len = 10, capacity = 100, spare has 0xFF
///
/// fast_zeroize_vec(&mut vec);
/// assert!(is_vec_fully_zeroized(&vec));
/// ```
#[inline(always)]
pub fn fast_zeroize_vec<T>(vec: &mut Vec<T>) {
    if vec.capacity() == 0 {
        return;
    }

    let byte_len = vec.capacity() * core::mem::size_of::<T>();
    unsafe {
        core::ptr::write_bytes(vec.as_mut_ptr() as *mut u8, 0, byte_len);
        // Volatile read prevents the optimizer from removing the write_bytes
        core::ptr::read_volatile(vec.as_ptr() as *const u8);
    }
}

/// Zeroizes only the spare capacity of a Vec, leaving active elements untouched.
///
/// This zeros the memory region between `len` and `capacity`. Useful when
/// elements have already been zeroized individually (e.g., complex types with
/// internal pointers) and only the spare capacity needs cleanup.
///
/// # Example
///
/// ```
/// use memutil::zeroize_spare_capacity;
///
/// let mut vec = vec![0xFFu8; 100];
/// vec.truncate(10);  // len = 10, capacity = 100, spare has 0xFF
///
/// // Zero only spare capacity, leaving first 10 bytes as 0xFF
/// zeroize_spare_capacity(&mut vec);
///
/// assert!(vec.iter().all(|&b| b == 0xFF));  // Active elements unchanged
/// ```
#[inline(always)]
pub fn zeroize_spare_capacity<T>(vec: &mut Vec<T>) {
    let spare = vec.capacity() - vec.len();
    if spare == 0 {
        return;
    }

    let byte_len = spare * core::mem::size_of::<T>();
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len()) as *mut u8;
        core::ptr::write_bytes(spare_ptr, 0, byte_len);
        // Volatile read prevents optimizer from removing the write
        core::ptr::read_volatile(spare_ptr);
    }
}

/// Checks if the spare capacity of a Vec<T> is fully zeroized.
///
/// This function reads the spare capacity region (from len to capacity) at the
/// byte level without constructing any T values. Returns true if all bytes in
/// spare capacity are zero, or if there is no spare capacity.
///
/// # Safety
///
/// This is safe because:
/// - We only read bytes, never construct T values
/// - Vec guarantees the allocation is valid for capacity elements
/// - We only access memory between len and capacity
///
/// # Example
///
/// ```
/// use memutil::{zeroize_spare_capacity, is_spare_capacity_zeroized};
///
/// let mut vec = vec![1u32, 2, 3, 4, 5];
/// vec.truncate(2);  // len = 2, capacity = 5, spare has old data
///
/// assert!(!is_spare_capacity_zeroized(&vec));
///
/// zeroize_spare_capacity(&mut vec);
/// assert!(is_spare_capacity_zeroized(&vec));
/// ```
#[inline(never)]
pub fn is_spare_capacity_zeroized<T>(vec: &Vec<T>) -> bool {
    let len = vec.len();
    let cap = vec.capacity();

    if cap == len {
        return true; // No spare capacity
    }

    let len_bytes = len * core::mem::size_of::<T>();
    let cap_bytes = cap * core::mem::size_of::<T>();

    unsafe {
        let spare_ptr = vec.as_ptr().cast::<u8>().add(len_bytes);
        let spare_len = cap_bytes - len_bytes;
        core::slice::from_raw_parts(spare_ptr, spare_len)
            .iter()
            .all(|&b| b == 0)
    }
}

/// Attempts to split a mutable slice at the given index.
///
/// Returns `None` if `mid > slice.len()`, otherwise returns `Some((left, right))`
/// where `left = &mut slice[..mid]` and `right = &mut slice[mid..]`.
///
/// This is the fallible version of [`slice::split_at_mut`], which panics on out-of-bounds.
///
/// # Example
///
/// ```
/// use memutil::try_split_at_mut;
///
/// let mut data = [1, 2, 3, 4, 5];
///
/// // Valid split
/// let (left, right) = try_split_at_mut(&mut data, 2).unwrap();
/// assert_eq!(left, &[1, 2]);
/// assert_eq!(right, &[3, 4, 5]);
///
/// // Out of bounds
/// assert!(try_split_at_mut(&mut data, 10).is_none());
///
/// // Edge cases
/// let (left, right) = try_split_at_mut(&mut data, 0).unwrap();
/// assert_eq!(left, &[]);
/// assert_eq!(right, &[1, 2, 3, 4, 5]);
///
/// let (left, right) = try_split_at_mut(&mut data, 5).unwrap();
/// assert_eq!(left, &[1, 2, 3, 4, 5]);
/// assert_eq!(right, &[]);
/// ```
#[inline(always)]
pub fn try_split_at_mut<T>(slice: &mut [T], mid: usize) -> Option<(&mut [T], &mut [T])> {
    if mid <= slice.len() {
        Some(slice.split_at_mut(mid))
    } else {
        None
    }
}

/// Attempts to split a mutable slice from the end at the given size.
///
/// Returns `None` if `end_size > slice.len()`, otherwise returns `Some((left, right))`
/// where `right` has exactly `end_size` elements from the end of the slice.
///
/// This is useful for splitting off a fixed-size suffix (like a tag or checksum)
/// from the end of a buffer.
///
/// # Example
///
/// ```
/// use memutil::try_split_at_mut_from_end;
///
/// let mut data = [1, 2, 3, 4, 5];
///
/// // Split off last 2 elements
/// let (left, right) = try_split_at_mut_from_end(&mut data, 2).unwrap();
/// assert_eq!(left, &[1, 2, 3]);
/// assert_eq!(right, &[4, 5]);
///
/// // Out of bounds
/// assert!(try_split_at_mut_from_end(&mut data, 10).is_none());
///
/// // Edge cases
/// let (left, right) = try_split_at_mut_from_end(&mut data, 0).unwrap();
/// assert_eq!(left, &[1, 2, 3, 4, 5]);
/// assert_eq!(right, &[]);
///
/// let (left, right) = try_split_at_mut_from_end(&mut data, 5).unwrap();
/// assert_eq!(left, &[]);
/// assert_eq!(right, &[1, 2, 3, 4, 5]);
/// ```
#[inline(always)]
pub fn try_split_at_mut_from_end<T>(
    slice: &mut [T],
    end_size: usize,
) -> Option<(&mut [T], &mut [T])> {
    if end_size <= slice.len() {
        let split_point = slice.len() - end_size;
        Some(slice.split_at_mut(split_point))
    } else {
        None
    }
}
