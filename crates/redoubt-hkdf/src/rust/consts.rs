// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// SHA-512 output size in bytes
pub const HASH_LEN: usize = 64;

/// SHA-512 block size in bytes
pub const BLOCK_LEN: usize = 128;

/// Maximum output length for SHA-512: 255 * 64 = 16320 bytes
pub const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

/// SHA-256 output size in bytes
pub const SHA256_HASH_LEN: usize = 32;

/// SHA-256 block size in bytes
pub const SHA256_BLOCK_LEN: usize = 64;

/// Maximum output length for SHA-256: 255 * 32 = 8160 bytes
pub const SHA256_MAX_OUTPUT_LEN: usize = 255 * SHA256_HASH_LEN;
