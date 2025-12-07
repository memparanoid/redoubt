// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::fast_zeroize_slice;

/// Zeroize 128 bytes (SHA-512 block size)
#[inline(always)]
pub fn zeroize_128(buf: &mut [u8; 128]) {
    fast_zeroize_slice(buf);
}

/// Zeroize 64 bytes (SHA-512 output size)
#[inline(always)]
pub fn zeroize_64(buf: &mut [u8; 64]) {
    fast_zeroize_slice(buf);
}
