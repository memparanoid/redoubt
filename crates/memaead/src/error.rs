// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Common AEAD error types.

/// Errors that can occur during AEAD decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,

    /// Only used in tests with dynamic slices.
    #[cfg(test)]
    #[error("invalid nonce size")]
    InvalidNonceSize,

    /// Only used in tests with dynamic slices.
    #[cfg(test)]
    #[error("ciphertext too short")]
    CiphertextTooShort,
}
