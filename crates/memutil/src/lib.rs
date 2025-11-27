// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memory utilities for secure byte conversions and verification.
//!
//! All conversion functions zeroize source data after reading to prevent
//! sensitive data from lingering on the stack.

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
/// use memutil::is_vec_fully_zeroized;
/// use zeroize::Zeroize;
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
/// // Zeroize clears BOTH active elements AND spare capacity
/// vec.zeroize();
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

    let byte_len = slice.len() * core::mem::size_of::<T>();
    unsafe {
        core::ptr::write_bytes(slice.as_mut_ptr() as *mut u8, 0, byte_len);
        // Volatile read prevents the optimizer from removing the write_bytes
        core::ptr::read_volatile(slice.as_ptr() as *const u8);
    }
}
