// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

use memaead::DecryptError;
use memcodec::{DecodeError, EncodeError, OverflowError};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("EncodeError: {0}")]
    Encode(#[from] EncodeError),

    #[error("DecodeError: {0}")]
    Decode(#[from] DecodeError),

    #[error("DecryptError: {0}")]
    Decrypt(#[from] DecryptError),

    #[error("OverflowError: {0}")]
    Overflow(#[from] OverflowError),

    #[error("InvalidKeyLengthError")]
    InvalidKeyLength,

    #[error("AeadBufferNotZeroizedError")]
    AeadBufferNotZeroized,

    #[error("CiphertextTooShort")]
    CiphertextTooShort,
}
