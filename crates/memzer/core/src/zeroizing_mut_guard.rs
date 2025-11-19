// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt;
use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

use crate::collections::{
    collection_zeroed, to_zeroizable_dyn_mut, to_zeroization_probe_dyn_ref, zeroize_collection,
};

use super::assert::assert_zeroize_on_drop;
use super::drop_sentinel::DropSentinel;
use super::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    inner: &'a mut T,
    __drop_sentinel: DropSentinel,
}

impl<'a, T> fmt::Debug for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ZeroizingMutGuard]")
    }
}

impl<'a, T> ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    pub fn from(inner: &'a mut T) -> Self {
        Self {
            inner,
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl<'a, T> Deref for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a, T> DerefMut for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

impl<'a, T> Zeroizable for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn self_zeroize(&mut self) {
        let elements: [&mut dyn Zeroizable; 1] = [to_zeroizable_dyn_mut(&mut *self.inner)];
        zeroize_collection(&mut elements.into_iter());
    }
}

impl<'a, T> AssertZeroizeOnDrop for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn clone_drop_sentinel(&self) -> crate::drop_sentinel::DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl<'a, T> ZeroizationProbe for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        let elements: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&*self.inner)];
        collection_zeroed(&mut elements.into_iter())
    }
}
