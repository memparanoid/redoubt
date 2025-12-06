// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PortableBuffer - Standard allocation buffer (no-op security)
//!
//! Works everywhere, no special memory protection.
//! Used as fallback when ProtectedBuffer is not available.

extern crate alloc;

use alloc::vec::Vec;

use memzer::{DropSentinel, FastZeroizable, MemZer};

use crate::error::ProtectedBufferError;
use crate::traits::Buffer;

#[derive(MemZer)]
#[memzer(drop)]
pub struct PortableBuffer {
    inner: Vec<u8>,
    __drop_sentinel: DropSentinel,
}

impl PortableBuffer {
    pub fn create(len: usize) -> Self {
        let mut inner = Vec::with_capacity(len);
        // Safety: we just allocated this capacity, setting len to capacity
        // leaves uninitialized memory but open_mut will handle it
        unsafe {
            inner.set_len(len);
        }

        Self {
            inner,
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl Buffer for PortableBuffer {
    fn open<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&[u8]) -> Result<(), ProtectedBufferError>,
    {
        f(&self.inner)
    }

    fn open_mut<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&mut [u8]) -> Result<(), ProtectedBufferError>,
    {
        f(&mut self.inner)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}
