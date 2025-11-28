// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::error;
use core::fmt;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodecBufferError {
    #[error("CapacityExceeded")]
    CapacityExceeded,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DecodeBufferError {
    #[error("OutOfBounds")]
    OutOfBounds,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EncodeError {
    #[error("OverflowError: {0}")]
    OverflowError(#[from] OverflowError),

    #[error("CodecBufferError: {0}")]
    CodecBufferError(#[from] CodecBufferError),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DecodeError {
    #[error("DecodeBufferError: {0}")]
    DecodeBufferError(#[from] DecodeBufferError),

    #[error("PreconditionViolated")]
    PreconditionViolated,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OverflowError {
    pub reason: String,
}

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Overflow Error")
    }
}

impl error::Error for OverflowError {}
