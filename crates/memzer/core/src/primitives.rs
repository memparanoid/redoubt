// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wrapper types for primitive scalars with [`DropSentinel`](crate::DropSentinel) support.
//!
//! This module provides wrapper types (`U8`, `U16`, `U32`, `U64`, `U128`, `USIZE`) that wrap
//! primitive integer types and add zeroization verification via [`DropSentinel`](crate::DropSentinel).

use zeroize::Zeroize;

macro_rules! impl_primitives_mem_zer_traits {
    ($(($ty:ty, $fn_name:ident, $wrapper_ty:ident)),* $(,)?) => {
        $(
            #[doc = concat!("Wrapper for `", stringify!($ty), "` with [`DropSentinel`](crate::DropSentinel) support.")]
            ///
            /// This type wraps a primitive integer and adds zeroization verification.
            /// On drop, it verifies that `.zeroize()` was called via the embedded sentinel.
            #[derive(Zeroize, Eq, PartialEq)]
            #[zeroize(drop)]
            #[cfg_attr(test, derive(Debug))]
            pub struct $wrapper_ty(pub $ty, pub $crate::drop_sentinel::DropSentinel);

            impl Default for $wrapper_ty {
                fn default() -> Self {
                    Self(0 as $ty, $crate::drop_sentinel::DropSentinel::default())
                }
            }

            #[doc = concat!("Creates a new default `", stringify!($wrapper_ty), "` (value = 0).")]
            pub fn $fn_name() -> $wrapper_ty {
                $wrapper_ty::default()
            }

            impl $wrapper_ty {
                /// Exposes an immutable reference to the inner value.
                pub fn expose(&self) -> &$ty {
                    &self.0
                }

                /// Exposes a mutable reference to the inner value.
                pub fn expose_mut(&mut self) -> &mut $ty {
                    &mut self.0
                }
            }

            impl $crate::traits::ZeroizationProbe for $ty {
                #[inline(always)]
                fn is_zeroized(&self) -> bool {
                    self.to_le_bytes().iter().all(|b| *b == 0)
                }
            }

            impl $crate::traits::Zeroizable for $ty {
                #[inline(always)]
                fn self_zeroize(&mut self) {
                    self.zeroize();
                }

            }

            impl $crate::traits::ZeroizationProbe for $wrapper_ty {
                #[inline(always)]
                fn is_zeroized(&self) -> bool {
                    self.0 == 0
                }
            }

            impl $crate::traits::Zeroizable for $wrapper_ty {
                #[inline(always)]
                fn self_zeroize(&mut self) {
                    self.zeroize();
                }

            }

            impl $crate::traits::AssertZeroizeOnDrop for $wrapper_ty {
                fn clone_drop_sentinel(&self) -> $crate::drop_sentinel::DropSentinel {
                    self.1.clone()
                }

                fn assert_zeroize_on_drop(self) {
                  $crate::assert::assert_zeroize_on_drop(self)
                }
            }
        )*
    };
}

impl_primitives_mem_zer_traits!(
    (u8, u8, U8),
    (u16, u16, U16),
    (u32, u32, U32),
    (u64, u64, U64),
    (u128, u128, U128),
    (usize, usize, USIZE)
);

// Implement ZeroizationProbe for bool
impl crate::traits::ZeroizationProbe for bool {
    #[inline(always)]
    fn is_zeroized(&self) -> bool {
        !(*self)
    }
}

impl crate::traits::Zeroizable for bool {
    #[inline(always)]
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// FastZeroize implementations
// =============================================================================

/// Implements FastZeroize for primitive numeric types.
macro_rules! impl_fast_zeroize_primitive {
    ($($ty:ty),* $(,)?) => {
        $(
            impl crate::traits::FastZeroize for $ty {
                const CAN_BE_BULK_ZEROIZED: bool = true;

                #[inline(always)]
                fn fast_zeroize(&mut self) {
                    memutil::zeroize_primitive(self);
                }
            }
        )*
    };
}

impl_fast_zeroize_primitive!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char
);
