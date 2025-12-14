// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Collection utilities for zero-copy moves.
use alloc::vec::Vec;

use core::mem;

use redoubt_zero::{FastZeroizable, ZeroizeMetadata};

use crate::MemMove;

/// Moves data from `src` slice to `dst` slice using `core::mem::take`.
///
/// This function transfers elements from `src` to `dst`, zeroizing
/// `src` in the process via `mem::take` (which replaces source with Default).
///
/// Moves `min(src.len(), dst.len())` elements (best-effort, panic-free).
#[inline]
pub(crate) fn move_slice<T: Default>(src: &mut [T], dst: &mut [T]) {
    let count = src.len().min(dst.len());

    for i in 0..count {
        dst[i] = mem::take(&mut src[i]);
    }
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

// Implement for common element types
impl_mem_move_array!(u8, u16, u32, u64, u128, usize);

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

// Implement for common element types
impl_mem_move_vec!(u8, u16, u32, u64, u128, usize);
