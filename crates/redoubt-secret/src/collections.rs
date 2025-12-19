// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Collection utilities for zero-copy moves.
use alloc::vec::Vec;
use core::mem;

use redoubt_alloc::{RedoubtString, RedoubtVec};
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::MemMove;

/// Moves data from `src` slice to `dst` slice using `ptr::copy_nonoverlapping`.
///
/// This function transfers elements from `src` to `dst`, zeroizing
/// `src` in the process via `fast_zeroize`. This is significantly faster
/// than per-element moves for large slices.
///
/// Moves `min(src.len(), dst.len())` elements (best-effort, panic-free).
///
/// # Performance Note
///
/// Uses `ptr::copy_nonoverlapping` for bulk copy instead of individual
/// `mem::take` operations, which is much faster for large slices.
#[inline]
pub(crate) fn move_slice<T: FastZeroizable + ZeroizeMetadata>(src: &mut [T], dst: &mut [T]) {
    let count = src.len().min(dst.len());

    unsafe {
        // SAFETY (PRECONDITIONS ARE MET): copying exactly count elements from valid slices
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), count);
    }

    // Zeroize source
    src.fast_zeroize();
}

/// Moves a `Vec<T>` from `src` to `dst`, zeroizing `dst` before reserve.
///
/// This function:
/// 1. Zeroizes `dst` (clearing both elements AND spare capacity)
/// 2. Reserves exact capacity in `dst` for `src.len()` elements
/// 3. Moves ownership from `src` to `dst` (src becomes empty)
///
/// This ensures no unzeroized data remains in `dst`'s spare capacity
/// before expanding.
#[inline]
pub(crate) fn move_vec<T: FastZeroizable + ZeroizeMetadata>(src: &mut Vec<T>, dst: &mut Vec<T>) {
    // CRITICAL: Zeroize dst to clear spare capacity BEFORE taking ownership
    dst.fast_zeroize();

    // Reserve exact capacity to avoid reallocation
    dst.reserve_exact(src.len());

    // Move ownership from src to dst (src becomes empty Vec)
    *dst = mem::take(src);
}

/// Macro to implement `MemMove` for fixed-size arrays of any size.
macro_rules! impl_mem_move_array {
    ($($t:ty),* $(,)?) => {
        $(
            impl<const N: usize> MemMove for [$t; N] {
                fn mem_move(src: &mut Self, dst: &mut Self) {
                    move_slice(&mut src[..], &mut dst[..]);
                }
            }
        )*
    };
}

// Implement for all primitive types
impl_mem_move_array!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, bool,
);

/// Macro to implement `MemMove` for `Vec<T>`.
macro_rules! impl_mem_move_vec {
    ($($t:ty),* $(,)?) => {
        $(
            impl MemMove for Vec<$t> {
                fn mem_move(src: &mut Self, dst: &mut Self) {
                    move_vec(src, dst);
                }
            }
        )*
    };
}

// Implement for all primitive types
impl_mem_move_vec!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, bool,
);

/// Implement `MemMove` for `RedoubtVec<T>`.
///
/// Moves data from `src` to `dst` by draining the slice, which
/// automatically zeroizes the source.
impl<T> MemMove for RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    fn mem_move(src: &mut Self, dst: &mut Self) {
        dst.clear();

        // Get mutable slice from src (via DerefMut)
        let src_slice = &mut **src;

        // Extend dst from src (this zeroizes src_slice)
        dst.extend_from_mut_slice(src_slice);

        // Clear src length (data already zeroized)
        src.clear();
    }
}

/// Implement `MemMove` for `RedoubtString`.
///
/// Moves data from `src` to `dst` using `extend_from_mut_string`, which
/// automatically zeroizes the source without creating temporary copies.
impl MemMove for RedoubtString {
    fn mem_move(src: &mut Self, dst: &mut Self) {
        dst.clear();

        // Get mutable reference to inner String
        let src_inner = src.as_mut_string();

        // Extend dst from src (zeroizes src_inner automatically)
        dst.extend_from_mut_string(src_inner);

        // Clear src length (data already zeroized by extend_from_mut_string)
        src.clear();
    }
}
