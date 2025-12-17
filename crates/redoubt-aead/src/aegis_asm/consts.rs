// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L constants and type aliases.

/// Key size: 128 bits (16 bytes)
pub(crate) const KEY_SIZE: usize = 16;
/// Nonce size: 128 bits (16 bytes)
pub(crate) const NONCE_SIZE: usize = 16;
/// Tag size: 128 bits (16 bytes)
pub(crate) const TAG_SIZE: usize = 16;
/// Block size: 256 bits (32 bytes)
pub(crate) const BLOCK_SIZE: usize = 32;

/// AEGIS-128L key type
pub(crate) type Aegis128LKey = [u8; KEY_SIZE];
/// AEGIS-128L nonce type
pub(crate) type Aegis128LNonce = [u8; NONCE_SIZE];
/// AEGIS-128L tag type
pub(crate) type Aegis128LTag = [u8; TAG_SIZE];
