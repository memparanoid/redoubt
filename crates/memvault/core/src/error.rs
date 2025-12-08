// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault error types

use thiserror::Error;

use membuffer::BufferError as MemBufferError;
use memcodec::{DecodeError, EncodeError, OverflowError};
use memcrypt::CryptoError;
use memhkdf::HkdfError;
use memrand::EntropyError;

#[derive(Debug, Error)]
pub enum BufferError {
    #[error(transparent)]
    Buffer(#[from] MemBufferError),

    #[error("buffer mutex poisoned")]
    Poisoned,
}

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
