// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::string::String;

use core::error;
use core::fmt;

#[derive(Debug, Eq, PartialEq)]
pub enum RedoubtCodecBufferError {
    CapacityExceeded,
}

impl fmt::Display for RedoubtCodecBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded => {
                f.write_str("the buffer is full: what is written does not fit its capacity")
            }
        }
    }
}

impl error::Error for RedoubtCodecBufferError {}

#[derive(Debug, Eq, PartialEq)]
pub enum DecodeBufferError {
    OutOfBounds,
}

impl fmt::Display for DecodeBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("the bytes end before what is read from them"),
        }
    }
}

impl error::Error for DecodeBufferError {}

#[derive(Debug, Eq, PartialEq)]
pub enum EncodeError {
    OverflowError(OverflowError),

    RedoubtCodecBufferError(RedoubtCodecBufferError),

    /// Test-only error for simulating encode failures.
    ///
    /// Available only with `test-utils` feature enabled.
    #[cfg(any(test, feature = "test-utils"))]
    IntentionalEncodeError,
}

impl From<OverflowError> for EncodeError {
    fn from(overflow_error: OverflowError) -> Self {
        Self::OverflowError(overflow_error)
    }
}

impl From<RedoubtCodecBufferError> for EncodeError {
    fn from(buffer_error: RedoubtCodecBufferError) -> Self {
        Self::RedoubtCodecBufferError(buffer_error)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverflowError(overflow_error) => fmt::Display::fmt(overflow_error, f),
            Self::RedoubtCodecBufferError(buffer_error) => fmt::Display::fmt(buffer_error, f),
            #[cfg(any(test, feature = "test-utils"))]
            Self::IntentionalEncodeError => f.write_str("a test behaviour refused to encode"),
        }
    }
}

impl error::Error for EncodeError {}

#[derive(Debug, Eq, PartialEq)]
pub enum DecodeError {
    DecodeBufferError(DecodeBufferError),

    PreconditionViolated,

    UnknownTag {
        tag: u64,
    },

    /// Test-only error for simulating decode failures.
    ///
    /// Available only with `test-utils` feature enabled.
    #[cfg(any(test, feature = "test-utils"))]
    IntentionalDecodeError,
}

impl From<DecodeBufferError> for DecodeError {
    fn from(buffer_error: DecodeBufferError) -> Self {
        Self::DecodeBufferError(buffer_error)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodeBufferError(buffer_error) => fmt::Display::fmt(buffer_error, f),
            Self::PreconditionViolated => {
                f.write_str("the bytes are not an encoding of what is decoded into")
            }
            Self::UnknownTag { tag } => write!(f, "the tag {tag} names no variant"),
            #[cfg(any(test, feature = "test-utils"))]
            Self::IntentionalDecodeError => f.write_str("a test behaviour refused to decode"),
        }
    }
}

impl error::Error for DecodeError {}

#[derive(Debug, PartialEq, Eq)]
pub struct OverflowError {
    pub reason: String,
}

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the encoded size would be past usize::MAX: {}",
            self.reason
        )
    }
}

impl error::Error for OverflowError {}
