// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ops::{Deref, DerefMut};

#[cfg(feature = "zeroize")]
use memzer::{FastZeroizable, ZeroizeMetadata};

#[repr(transparent)]
#[cfg(feature = "zeroize")]
pub struct Zeroizing<T: FastZeroizable>(T);

#[repr(transparent)]
#[cfg(not(feature = "zeroize"))]
pub struct Zeroizing<T>(T);

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable + Default> Zeroizing<T> {
    #[inline(always)]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn from(value: &mut T) -> Self {
        Self(core::mem::take(value))
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Default> Zeroizing<T> {
    #[inline(always)]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn from(value: &mut T) -> Self {
        Self(core::mem::take(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable> Deref for Zeroizing<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> Deref for Zeroizing<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable> DerefMut for Zeroizing<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> DerefMut for Zeroizing<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable> ZeroizeMetadata for Zeroizing<T> {
    const CAN_BE_BULK_ZEROIZED: bool = true;
}

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable> FastZeroizable for Zeroizing<T> {
    fn fast_zeroize(&mut self) {
        self.0.fast_zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: FastZeroizable> Drop for Zeroizing<T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.fast_zeroize();
    }
}
