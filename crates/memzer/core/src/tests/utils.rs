// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Return `true` if every byte in the N sized array is zero.
#[inline]
pub fn is_zeroed_array<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Return `true` if the *entire allocation* of `vec` (0..capacity) contains zeros.
///
/// # Safety
/// This function reads the whole allocation, including the "spare capacity".
/// Only call this after a routine that has **explicitly written** to the entire
/// allocation (e.g. a secure wipe that zeros len and spare capacity).
#[inline(never)]
pub fn is_zeroed_vec(vec: &Vec<u8>) -> bool {
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

/// Return `true` if every byte in the slice is zero.
#[inline(never)]
pub fn is_zeroed_slice(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}
