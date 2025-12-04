// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations for primitive types.
//!
//! This module provides `ZeroizationProbe`, `ZeroizeMetadata`, and `FastZeroizable`
//! implementations for all Rust primitive types.

/// Implements ZeroizationProbe for integer types using to_le_bytes().
macro_rules! impl_zeroization_probe_int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl crate::traits::ZeroizationProbe for $ty {
                #[inline(always)]
                fn is_zeroized(&self) -> bool {
                    self.to_le_bytes().iter().all(|b| *b == 0)
                }
            }
        )*
    };
}

/// Implements ZeroizationProbe for bool (false is zeroized).
impl crate::traits::ZeroizationProbe for bool {
    #[inline(always)]
    fn is_zeroized(&self) -> bool {
        !(*self)
    }
}

/// Implements ZeroizationProbe for char (null char is zeroized).
impl crate::traits::ZeroizationProbe for char {
    #[inline(always)]
    fn is_zeroized(&self) -> bool {
        *self == '\0'
    }
}

impl_zeroization_probe_int!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);

/// Implements FastZeroizable and ZeroizeMetadata for all primitive types.
macro_rules! impl_fast_zeroize_primitive {
    ($($ty:ty),* $(,)?) => {
        $(
            impl crate::traits::ZeroizeMetadata for $ty {
                const CAN_BE_BULK_ZEROIZED: bool = true;
            }

            impl crate::traits::FastZeroizable for $ty {
                #[inline(always)]
                fn fast_zeroize(&mut self) {
                    memutil::zeroize_primitive(self);
                }
            }
        )*
    };
}

impl_fast_zeroize_primitive!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, bool, char,
);
