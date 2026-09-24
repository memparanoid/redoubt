// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata};

/// An optional value wrapper with automatic zeroization.
#[derive(RedoubtZero, Default)]
#[fast_zeroize(drop)]
pub struct RedoubtOption<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Option<T>,
    /// Runtime verification that zeroization happened, for the tests that
    /// read it.
    ///
    /// Gated because it is an `Arc<AtomicBool>` — one heap allocation per
    /// value, in a type whose whole reason for existing is to leave nothing
    /// in memory. Nothing reads it outside this crate's own tests, and the
    /// `RedoubtZero` derive treats the field as optional.
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl<T> RedoubtOption<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    /// Returns a reference to the inner value, or `None`.
    pub fn as_ref(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    /// Returns a mutable reference to the inner value, or `None`.
    pub fn as_mut(&mut self) -> Option<&mut T> {
        self.inner.as_mut()
    }

    /// Replaces the inner value with a new one, zeroizing both the old value and the source.
    pub fn replace(&mut self, value: &mut T)
    where
        T: Default,
    {
        // Zeroize old value if Some
        if let Some(old) = &mut self.inner {
            old.fast_zeroize();
        }

        // Move new value from source
        let slot = self.inner.get_or_insert_with(T::default);

        redoubt_mem::swap(value, slot);

        // Zeroize source
        value.fast_zeroize();
    }

    /// Returns `true` if the option contains a value.
    pub fn is_some(&self) -> bool {
        self.inner.is_some()
    }

    /// Returns `true` if the option is `None`.
    pub fn is_none(&self) -> bool {
        self.inner.is_none()
    }

    /// Returns a reference to the inner `Option<T>`.
    #[inline(always)]
    pub fn as_option(&self) -> &Option<T> {
        &self.inner
    }

    /// Returns a mutable reference to the inner `Option<T>`.
    #[inline(always)]
    pub fn as_mut_option(&mut self) -> &mut Option<T> {
        &mut self.inner
    }
}
