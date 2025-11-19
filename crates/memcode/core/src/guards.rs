// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

pub(crate) struct PrimitiveGuard<'a, T: Zeroize> {
    inner: &'a mut T,
}

impl<'a, T: Zeroize> PrimitiveGuard<'a, T> {
    pub fn from(t: &'a mut T) -> Self {
        Self { inner: t }
    }
}

impl<'a, T: Zeroize> AsRef<T> for PrimitiveGuard<'a, T> {
    fn as_ref(&self) -> &T {
        self.inner
    }
}

impl<'a, T: Zeroize> Drop for PrimitiveGuard<'a, T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

pub struct BytesGuard<'a> {
    bytes: &'a mut [u8],
}

impl<'a> BytesGuard<'a> {
    pub fn from(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> AsRef<[u8]> for BytesGuard<'a> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl<'a> AsMut<[u8]> for BytesGuard<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

impl<'a> Drop for BytesGuard<'a> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
