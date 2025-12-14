// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Common AEAD error types.

/// Errors that can occur during AEAD operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,

    #[error("invalid key size")]
    InvalidKeySize,

    #[error("invalid nonce size")]
    InvalidNonceSize,

    #[error("invalid tag size")]
    InvalidTagSize,
}
