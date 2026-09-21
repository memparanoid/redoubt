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
        // SAFETY: what is written to is `&mut self`, so it is live, aligned
        // and the only reference to itself. A null pointer is a value every
        // `*mut T` admits — what it points at is the caller's to answer for,
        // and after this it points at nothing.
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
        // SAFETY: what is written to is `&mut self`, so it is live, aligned
        // and the only reference to itself. A null pointer is a value every
        // `*const T` admits — what it points at is the caller's to answer
        // for, and after this it points at nothing.
        unsafe {
            ptr::write_volatile(self, ptr::null());
        }
    }
}
