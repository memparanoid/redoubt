// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod primitive {
    use core::ops::{Deref, DerefMut};

    #[cfg(feature = "zeroize")]
    use memzer::{FastZeroizable, ZeroizeMetadata};

    #[repr(transparent)]
    #[cfg(feature = "zeroize")]
    pub struct Primitive<T: FastZeroizable>(T);

    #[repr(transparent)]
    #[cfg(not(feature = "zeroize"))]
    pub struct Primitive<T>(T);

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> Primitive<T> {
        #[inline(always)]
        pub fn new(value: T) -> Self {
            Self(value)
        }
    }

    #[cfg(not(feature = "zeroize"))]
    impl<T> Primitive<T> {
        #[inline(always)]
        pub fn new(value: T) -> Self {
            Self(value)
        }
    }

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> Deref for Primitive<T> {
        type Target = T;

        #[inline(always)]
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(not(feature = "zeroize"))]
    impl<T> Deref for Primitive<T> {
        type Target = T;

        #[inline(always)]
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> DerefMut for Primitive<T> {
        #[inline(always)]
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[cfg(not(feature = "zeroize"))]
    impl<T> DerefMut for Primitive<T> {
        #[inline(always)]
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> ZeroizeMetadata for Primitive<T> {
        const CAN_BE_BULK_ZEROIZED: bool = true;
    }

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> FastZeroizable for Primitive<T> {
        fn fast_zeroize(&mut self) {
            self.0.fast_zeroize();
        }
    }

    #[cfg(feature = "zeroize")]
    impl<T: FastZeroizable> Drop for Primitive<T> {
        #[inline(always)]
        fn drop(&mut self) {
            self.0.fast_zeroize();
        }
    }
}

pub use primitive::Primitive;
