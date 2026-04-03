// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Type aliases for AEAD.

use super::consts::{KEY_SIZE, XNONCE_SIZE};

/// AEAD key type
pub type AeadKey = [u8; KEY_SIZE];

/// XChaCha20 nonce type
pub type XNonce = [u8; XNONCE_SIZE];
