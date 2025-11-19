// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemDecodeError {
    #[error("CoerceError: {0}")]
    CoerceError(#[from] CoerceError),

    #[error("preconditions violated error")]
    PreconditionsViolatedError,

    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: usize, got: usize },

    #[cfg(test)]
    #[error("TestBreakerIntentionalDecodeError")]
    TestBreakerIntentionalDecodeError,
}

#[derive(Debug, Error)]
pub enum WordBufError {
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),

    #[error("capacity exceeded error")]
    CapacityExceededError,
}

#[derive(Debug, Error)]
pub enum MemEncodeError {
    #[error("CoerceError: {0}")]
    CoerceError(#[from] CoerceError),

    #[error("WordBufError: {0}")]
    WordBufError(#[from] WordBufError),

    #[cfg(test)]
    #[error("TestBreakerIntentionalEncodeError")]
    TestBreakerIntentionalEncodeError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoerceError {
    #[error(
        "out of range: value={value} (expected in [{min}..={max}]) when coercing `{src}` -> `{dst}`"
    )]
    OutOfRange {
        value: u128,
        min: u128,
        max: u128,
        src: &'static str,
        dst: &'static str,
    },

    #[error("LengthMismatchError")]
    LengthMismatchError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("word stream length is not a multiple of 4 bytes (got {got} bytes)")]
    InvalidWordStreamLenError { got: usize },
}
