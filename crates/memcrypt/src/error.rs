// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

use memaead::AeadError;
use memcodec::{DecodeError, EncodeError, OverflowError};

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
