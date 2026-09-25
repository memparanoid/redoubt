// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether bytes spell UTF-8, leaving none of them in a register.

use redoubt_asm::Backend;

use crate::backend;

/// Whether `bytes` are UTF-8, as [`core::str::from_utf8`] would answer, with
/// none of them left behind in a register.
///
/// Not constant time: how long it takes says where the multibyte sequences are
/// and where the first byte that is not UTF-8 is. Where there is no assembly
/// the check reads one byte at a time: there is no erasure, and no load wider
/// than a byte either.
///
/// ```
/// assert!(redoubt_mem_core::is_utf8("añejo".as_bytes()));
/// assert!(!redoubt_mem_core::is_utf8(&[0xC0, 0x80]));
/// ```
#[inline]
pub fn is_utf8(bytes: &[u8]) -> bool {
    is_utf8_with_backend(Backend::default(), bytes)
}

/// [`is_utf8`], through the backend named.
#[inline]
pub fn is_utf8_with_backend(backend: Backend, bytes: &[u8]) -> bool {
    backend::is_utf8(backend, bytes)
}
