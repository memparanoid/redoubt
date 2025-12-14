// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations for atomic types.
//!
//! This module provides `ZeroizationProbe`, `ZeroizeMetadata`, and `FastZeroizable`
//! implementations for all Rust atomic types.

use core::sync::atomic::Ordering;

/// Implements ZeroizationProbe, ZeroizeMetadata, and FastZeroizable for atomic integer types.
macro_rules! impl_fast_zeroize_atomic_int {
    ($($ty:ty => $zero:expr),* $(,)?) => {
        $(
            impl crate::traits::ZeroizationProbe for $ty {
                #[inline(always)]
                fn is_zeroized(&self) -> bool {
                    self.load(Ordering::Relaxed) == $zero
                }
            }

            impl crate::traits::ZeroizeMetadata for $ty {
                const CAN_BE_BULK_ZEROIZED: bool = false;
            }

            impl crate::traits::FastZeroizable for $ty {
                #[inline(always)]
                fn fast_zeroize(&mut self) {
                    self.store($zero, Ordering::Relaxed);
                }
            }
        )*
    };
}

use core::sync::atomic::{AtomicBool, AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicIsize};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize};

impl_fast_zeroize_atomic_int!(
    AtomicBool => false,
    AtomicU8 => 0,
    AtomicU16 => 0,
    AtomicU32 => 0,
    AtomicU64 => 0,
    AtomicUsize => 0,
    AtomicI8 => 0,
    AtomicI16 => 0,
    AtomicI32 => 0,
    AtomicI64 => 0,
    AtomicIsize => 0,
);
