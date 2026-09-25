// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether bytes are all zero, leaving none of them in a register.

use redoubt_asm::Backend;

use crate::backend;

/// Whether every one of `bytes` is zero, with none of them left behind in a
/// register.
///
/// Every byte is read, whatever the first one was. Where there is no assembly
/// the check reads one byte at a time: there is no erasure, and no load wider
/// than a byte either.
///
/// ```
/// assert!(redoubt_mem_core::is_zeroized(&[0; 32]));
/// assert!(!redoubt_mem_core::is_zeroized(&[0, 0, 1, 0]));
/// ```
#[inline]
pub fn is_zeroized(bytes: &[u8]) -> bool {
    is_zeroized_with_backend(Backend::default(), bytes)
}

/// [`is_zeroized`], through the backend named.
#[inline]
pub fn is_zeroized_with_backend(backend: Backend, bytes: &[u8]) -> bool {
    backend::is_zeroized(backend, bytes)
}
