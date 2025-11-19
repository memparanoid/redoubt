// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::MaybeUninit;

use chacha20poly1305::aead::Buffer;
use zeroize::Zeroize;

use memguard::assert::assert_zeroize_on_drop;
use memguard::{AssertZeroizeOnDrop, DropSentinel, Zeroizable, ZeroizationProbe};

use crate::error::CryptoError;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapacityExceededError;

#[derive(Default, Zeroize)]
#[zeroize(drop)]
pub struct AeadBuffer {
    inner: Vec<u8>,
    __drop_sentinel: DropSentinel,
}

impl AsRef<[u8]> for AeadBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for AeadBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl AeadBuffer {
    #[inline(never)]
    fn is_vec_fully_zeroized(vec: &Vec<u8>) -> bool {
        let cap = vec.capacity();
        let base = vec.as_ptr();

        for i in 0..cap {
            unsafe {
                if *base.add(i) != 0 {
                    return false;
                }
            }
        }

        true
    }

    pub fn zeroized_reserve_exact(&mut self, capacity: usize) -> Result<(), CryptoError> {
        if !Self::is_vec_fully_zeroized(&self.inner) {
            return Err(CryptoError::AeadBufferNotZeroized);
        }

        self.inner.zeroize();
        self.inner.reserve_exact(capacity);
        Ok(())
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    fn try_drain_slice(&mut self, other: &mut [u8]) -> Result<(), CapacityExceededError> {
        let cur_len = self.len();
        let new_len = cur_len
            .checked_add(other.len())
            .ok_or(CapacityExceededError)?;

        if new_len > self.capacity() {
            return Err(CapacityExceededError);
        }

        // SAFETY NOTE (logic): we must not reallocate.
        // Compute the new length and bail out if it would exceed capacity.
        self.inner.resize_with(new_len, || 0);

        let dest = &mut self.inner[cur_len..new_len];

        for (target, src) in dest.iter_mut().zip(other.iter_mut()) {
            *target = core::mem::take(src);
        }

        Ok(())
    }

    pub fn drain_slice(&mut self, other: &mut [u8]) -> Result<(), CapacityExceededError> {
        let result = self.try_drain_slice(other);

        if result.is_err() {
            other.zeroize();
        }

        result
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn tamper<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Vec<u8>),
    {
        f(&mut self.inner)
    }
}

impl Buffer for AeadBuffer {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn truncate(&mut self, len: usize) {
        let (_, tail) = self.inner.split_at_mut(len);
        tail.zeroize();

        for b in self.inner.spare_capacity_mut() {
            *b = MaybeUninit::new(0);
        }

        self.inner.truncate(len);
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        let cur_len = self.len();
        let new_len = cur_len
            .checked_add(other.len())
            .ok_or(chacha20poly1305::aead::Error)?;

        if new_len > self.capacity() {
            return Err(chacha20poly1305::aead::Error);
        }

        self.inner.extend_from_slice(other);

        Ok(())
    }
}

impl std::fmt::Debug for AeadBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[AeadBuffer: protected]")
    }
}

impl Zeroizable for AeadBuffer {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for AeadBuffer {
    #[inline]
    fn is_zeroized(&self) -> bool {
        //@TODO: Inspect spare capacity?
        self.inner.iter().all(|&b| b == 0)
    }
}

impl AssertZeroizeOnDrop for AeadBuffer {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}
