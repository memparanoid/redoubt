// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PortableBuffer - Standard allocation buffer (no-op security)
//!
//! Works everywhere, no special memory protection.
//! Used as fallback when ProtectedBuffer is not available.

extern crate alloc;

use alloc::vec::Vec;

pub struct PortableBuffer {
    data: Vec<u8>,
}

impl PortableBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(data);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn zeroize(&mut self) {
        // Best-effort zeroization
        for byte in self.data.iter_mut() {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for PortableBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}
