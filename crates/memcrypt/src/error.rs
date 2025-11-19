// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

use memcode::{MemDecodeError, MemEncodeBufError, MemEncodeError, OverflowError};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("MemDecodeError: {0}")]
    MemDecode(#[from] MemDecodeError),

    #[error("MemEncodeError: {0}")]
    MemEncode(#[from] MemEncodeError),

    #[error("MemEncodeBufError: {0}")]
    MemEncodeBuf(#[from] MemEncodeBufError),

    #[error("OverflowError: {0}")]
    Overflow(#[from] OverflowError),

    #[error("DecryptError")]
    Decrypt,

    #[error("InvalidKeyLengthError")]
    InvalidKeyLength,

    #[error("AeadBufferNotZeroizedError")]
    AeadBufferNotZeroized,
}
