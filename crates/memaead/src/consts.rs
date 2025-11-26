// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Shared constants for AEAD and Poly1305.

/// Authentication tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Key size in bytes
pub const KEY_SIZE: usize = 32;

/// Block size in bytes (Poly1305 and padding)
pub const BLOCK_SIZE: usize = 16;

/// Nonce size in bytes (XChaCha20 extended nonce)
pub const NONCE_SIZE: usize = 24;
