// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations for raw pointers.
//!
//! Provides `ZeroizationProbe`, `ZeroizeMetadata`, and `FastZeroizable`
//! implementations for `*mut T` and `*const T`.

use core::ptr;

use crate::traits::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

// *mut T

impl<T> ZeroizationProbe for *mut T {
    #[inline(always)]
    fn is_zeroized(&self) -> bool {
        self.is_null()
    }
}

impl<T> ZeroizeMetadata for *mut T {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T> FastZeroizable for *mut T {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(self, ptr::null_mut());
        }
    }
}

// *const T

impl<T> ZeroizationProbe for *const T {
    #[inline(always)]
    fn is_zeroized(&self) -> bool {
        self.is_null()
    }
}

impl<T> ZeroizeMetadata for *const T {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T> FastZeroizable for *const T {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(self, ptr::null());
        }
    }
}
