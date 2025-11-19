// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
use core::error;
use core::fmt;

use thiserror::Error;

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

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemDecodeError {
    #[error("OverflowError: {0}")]
    OverflowError(#[from] OverflowError),

    #[error("InvariantViolated")]
    InvariantViolated,

    #[error("LengthMismatch[expected {expected}, got {got}]")]
    LengthMismatch { expected: usize, got: usize },

    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalDecodeError)")]
    IntentionalDecodeError,

    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalPrepareWithNumElementsError)")]
    IntentionalPrepareWithNumElementsError,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemEncodeBufError {
    #[error("CapacityExceededError")]
    CapacityExceededError,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemEncodeError {
    #[error("OverflowError: {0}")]
    OverflowError(#[from] OverflowError),

    #[error("MemEncodeBufError: {0}")]
    MemEncodeBufError(#[from] MemEncodeBufError),

    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalEncodeError)")]
    IntentionalEncodeError,
}
