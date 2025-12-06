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

impl PortableBuffer {}

impl Drop for PortableBuffer {
    fn drop(&mut self) {}
}
