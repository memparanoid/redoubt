// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memory utilities for verification and testing.

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
///
/// # Use Case
///
/// This function is used to verify that vectors are safe to expand without
/// leaking previous data. Before calling operations like `resize_with()` or
/// `reserve_exact()`, check that spare capacity is clean:
///
/// ```
/// use memutil::is_vec_fully_zeroized;
///
/// fn safe_expand(vec: &mut Vec<u8>, new_len: usize) -> Result<(), &'static str> {
///     if !is_vec_fully_zeroized(vec) {
///         return Err("Cannot expand: spare capacity contains unzeroized data");
///     }
///     vec.resize_with(new_len, || 0);
///     Ok(())
/// }
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
