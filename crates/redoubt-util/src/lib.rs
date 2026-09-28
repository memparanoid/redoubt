// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bulk zeroization of slices and vectors, and the probes that check it.
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
/// use redoubt_util::{fast_zeroize_vec, is_vec_fully_zeroized};
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
        // SAFETY: the bound is the `Vec`'s own capacity, so every offset is
        // inside its allocation, and what is read is a `u8`, for which every
        // bit pattern is a value.
        unsafe {
            if *base.add(i) != 0 {
                return false;
            }
        }
    }

    true
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
/// use redoubt_util::fast_zeroize_slice;
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

    // SAFETY: the length is the slice's own size in bytes, so the write stays
    // inside it, and `&mut [T]` is what makes it the only reference. The read
    // is of one byte the write just set.
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
/// use redoubt_util::{fast_zeroize_vec, is_vec_fully_zeroized};
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

    // SAFETY: the length is the `Vec`'s own capacity in bytes, so the write
    // stays inside its allocation — the spare past `len` included, which is
    // the point — and `&mut Vec<T>` is what makes it the only reference. The
    // read is of one byte the write just set.
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
/// use redoubt_util::zeroize_spare_capacity;
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

    // SAFETY: `len` is inside the capacity, so offsetting by it lands in the
    // allocation, and what is written from there is the difference between the
    // two — the spare, and no element the `Vec` is holding. The read is of one
    // byte the write just set.
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len()) as *mut u8;
        core::ptr::write_bytes(spare_ptr, 0, byte_len);
        // Volatile read prevents optimizer from removing the write
        core::ptr::read_volatile(spare_ptr);
    }
}

/// Checks if the spare capacity of a `Vec<T>` is fully zeroized.
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
/// use redoubt_util::{zeroize_spare_capacity, is_spare_capacity_zeroized};
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

    // SAFETY: both offsets come from the `Vec`'s own `len` and capacity, so
    // the range is the spare inside its allocation, and it is read as `u8`,
    // for which every bit pattern is a value — no `T` is built out of it.
    unsafe {
        let spare_ptr = vec.as_ptr().cast::<u8>().add(len_bytes);
        let spare_len = cap_bytes - len_bytes;
        core::slice::from_raw_parts(spare_ptr, spare_len)
            .iter()
            .all(|&b| b == 0)
    }
}
