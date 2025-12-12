// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault error types

use thiserror::Error;

use memaead::AeadError;
use membuffer::BufferError;
use memcodec::{DecodeError, EncodeError, OverflowError};
use memrand::EntropyError;

#[derive(Debug, Error)]
pub enum CipherBoxError {
    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error(transparent)]
    Encode(#[from] EncodeError),

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error(transparent)]
    Entropy(#[from] EntropyError),

    #[error(transparent)]
    Buffer(#[from] BufferError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Aead(#[from] AeadError),

    /// The CipherBox is in an irrecoverable state.
    ///
    /// This error occurs when a cryptographic operation fails partway through,
    /// leaving some fields decrypted (plaintext exposed in memory). For security,
    /// all exposed plaintext is immediately zeroized before returning this error.
    ///
    /// **The data is permanently lost.** The CipherBox cannot be recovered or
    /// used again after this error. This is intentional: security guarantees
    /// take precedence over data preservation.
    #[error("poisoned: box is in an irrecoverable state, exposed plaintext was zeroized")]
    Poisoned,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("EncodeError: {0}")]
    Encode(#[from] EncodeError),

    #[error("DecodeError: {0}")]
    Decode(#[from] DecodeError),

    #[error("OverflowError: {0}")]
    Overflow(#[from] OverflowError),

    #[error("AeadError: {0}")]
    Aead(#[from] AeadError),

    #[error("PlaintextTooLong")]
    PlaintextTooLong,

    #[error("CiphertextWithTagTooShort")]
    CiphertextWithTagTooShort,
}
