// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD error types.

use super::consts::TAG_SIZE;

#[cfg(test)]
use super::consts::XNONCE_SIZE;

/// Errors that can occur during AEAD decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[cfg(test)]
    #[error("invalid nonce size: expected {XNONCE_SIZE} bytes")]
    InvalidNonceSize,

    #[error("ciphertext too short: expected at least {TAG_SIZE} bytes")]
    CiphertextTooShort,

    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,
}
