// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Sensitive data wrappers with mandatory zeroization.
//!
//! These types ensure sensitive cryptographic material is zeroed before being dropped.
//! In debug builds, forgetting to call `zeroize()` will panic.

use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;

macro_rules! define_sensitive_array {
    ($name:ident, $elem:ty, $zero:expr) => {
        /// A fixed-size array that must be explicitly zeroized before drop.
        ///
        /// In debug builds, dropping without zeroizing will panic.
        /// This ensures developers don't forget to clean up sensitive data.
        pub(crate) struct $name<const N: usize>([$elem; N]);

        impl<const N: usize> $name<N> {
            /// Create a new zeroed sensitive array.
            #[inline]
            pub fn new() -> Self {
                Self([$zero; N])
            }

            /// Check if all elements are zero.
            #[inline]
            pub fn is_zeroed(&self) -> bool {
                self.0.iter().all(|&v| v == $zero)
            }
        }

        impl<const N: usize> Zeroize for $name<N> {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl<const N: usize> Deref for $name<N> {
            type Target = [$elem; N];

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<const N: usize> DerefMut for $name<N> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<const N: usize> Drop for $name<N> {
            fn drop(&mut self) {
                debug_assert!(
                    self.is_zeroed(),
                    concat!(
                        stringify!($name),
                        "<{}> dropped without zeroize()! \
                     This is a security bug - sensitive data left in memory."
                    ),
                    N
                );
            }
        }
    };
}

define_sensitive_array!(SensitiveArrayU8, u8, 0u8);
define_sensitive_array!(SensitiveArrayU32, u32, 0u32);

impl<const N: usize> SensitiveArrayU32<N> {
    /// Drain one u32 as little-endian bytes into dst, then zeroize the source slot.
    /// Accesses the source directly without intermediate variables to avoid stack copies.
    #[inline]
    pub fn drain_le(&mut self, index: usize, dst: &mut [u8]) {
        debug_assert!(dst.len() >= 4);

        dst[0] = self.0[index] as u8;
        dst[1] = (self.0[index] >> 8) as u8;
        dst[2] = (self.0[index] >> 16) as u8;
        dst[3] = (self.0[index] >> 24) as u8;

        self.0[index] = 0;
    }
}
