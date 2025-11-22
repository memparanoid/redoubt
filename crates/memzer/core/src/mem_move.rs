// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Implementations of `MemMove` trait for common types.

use crate::traits::MemMove;
use crate::utils::{move_slice, move_vec};

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
