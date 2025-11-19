// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

macro_rules! impl_primitives_mem_zer_traits {
    ($(($ty:ty, $fn_name:ident, $wrapper_ty:ident)),* $(,)?) => {
        $(
            #[derive(Zeroize, Eq, PartialEq)]
            #[zeroize(drop)]
            #[cfg_attr(test, derive(Debug))]
            pub struct $wrapper_ty(pub $ty, pub $crate::drop_sentinel::DropSentinel);

            impl Default for $wrapper_ty {
                fn default() -> Self {
                    Self(0 as $ty, $crate::drop_sentinel::DropSentinel::default())
                }
            }

            pub fn $fn_name() -> $wrapper_ty {
                $wrapper_ty::default()
            }

            impl $wrapper_ty {
                pub fn expose(&self) -> &$ty {
                    &self.0
                }

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
