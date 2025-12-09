// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault error types

use thiserror::Error;

use memaead::AeadError;
use membuffer::BufferError;
use memcodec::{DecodeError, EncodeError, OverflowError};
use memhkdf::HkdfError;
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
    Hkdf(#[from] HkdfError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),
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
