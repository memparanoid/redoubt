// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PortableBuffer - Standard allocation buffer (no-op security)
//!
//! Works everywhere, no special memory protection.
//! Used as fallback when ProtectedBuffer is not available.

extern crate alloc;

use alloc::vec::Vec;

use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel};

use crate::error::BufferError;
use crate::traits::Buffer;

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct PortableBuffer {
    inner: Vec<u8>,
    __sentinel: ZeroizeOnDropSentinel,
}

impl PortableBuffer {
    pub fn create(len: usize) -> Self {
        let inner = alloc::vec![0u8; len];

        Self {
            inner,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

// Safety: PortableBuffer owns its Vec and doesn't share references
unsafe impl Send for PortableBuffer {}
unsafe impl Sync for PortableBuffer {}

impl core::fmt::Debug for PortableBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PortableBuffer")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl Buffer for PortableBuffer {
    fn open(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        f(&self.inner)
    }

    fn open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        f(&mut self.inner)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}
