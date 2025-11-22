// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for encoding and decoding operations.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
use core::error;
use core::fmt;

use thiserror::Error;

/// Error indicating a size calculation overflowed `usize`.
///
/// Returned by [`MemBytesRequired::mem_bytes_required()`](crate::MemBytesRequired::mem_bytes_required)
/// when the total size exceeds the maximum value of `usize`.
///
/// # When This Occurs
///
/// - Encoding very large collections (>2^64 elements on 64-bit systems)
/// - Nested structures with multiplicative size growth
/// - Corrupted size headers during decoding
///
/// # Example
///
/// ```rust
/// use memcode_core::{OverflowError, MemBytesRequired};
///
/// // Simulate overflow scenario (simplified)
/// let error = OverflowError {
///     reason: "Collection size exceeds usize::MAX".into(),
/// };
///
/// assert_eq!(format!("{}", error), "Overflow Error");
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct OverflowError {
    /// Human-readable description of what caused the overflow.
    pub reason: String,
}

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Overflow Error")
    }
}

impl error::Error for OverflowError {}

/// Errors that can occur during decoding operations.
///
/// All variants ensure that consumed/partial data is zeroized before the error is returned.
///
/// # Error Handling Invariant
///
/// **Critical:** Even when decoding fails, all bytes consumed up to the error point
/// are zeroized. This prevents partial plaintext from leaking in error paths.
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemDecode, MemDecodeError};
///
/// let mut buffer = vec![0u8; 10]; // Too small
/// let mut decoded = Vec::<u8>::new();
///
/// match decoded.drain_from(&mut buffer) {
///     Err(MemDecodeError::InvariantViolated) => {
///         // Buffer is zeroized even though decoding failed
///         assert!(buffer.iter().all(|&b| b == 0));
///     }
///     _ => panic!("Expected InvariantViolated error"),
/// }
/// ```
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemDecodeError {
    /// Size calculation overflowed during decoding.
    #[error("OverflowError: {0}")]
    OverflowError(#[from] OverflowError),

    /// Decoding invariant was violated.
    ///
    /// Occurs when:
    /// - Buffer is too small for expected data
    /// - Collection header specifies invalid size
    /// - Data structure is corrupted
    #[error("InvariantViolated")]
    InvariantViolated,

    /// Expected length doesn't match actual length.
    ///
    /// Occurs during collection decoding when the header-specified element count
    /// doesn't match the type's expected structure.
    #[error("LengthMismatch[expected {expected}, got {got}]")]
    LengthMismatch {
        /// Expected number of elements.
        expected: usize,
        /// Actual number of elements found.
        got: usize,
    },

    /// Test-only error for simulating decode failures.
    ///
    /// Available only with `test_utils` feature enabled.
    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalDecodeError)")]
    IntentionalDecodeError,

    /// Test-only error for simulating collection preparation failures.
    ///
    /// Available only with `test_utils` feature enabled.
    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalPrepareWithNumElementsError)")]
    IntentionalPrepareWithNumElementsError,
}

/// Errors specific to [`MemEncodeBuf`](crate::MemEncodeBuf) operations.
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemEncodeBuf, MemEncodeBufError};
///
/// let mut buf = MemEncodeBuf::new(2);
/// let value = 0xdeadbeef_u32;
/// let mut bytes = value.to_le_bytes();
///
/// match buf.drain_bytes(&mut bytes) {
///     Err(MemEncodeBufError::CapacityExceededError) => {
///         // Buffer was too small (needs 4 bytes, has 2)
///     }
///     _ => panic!("Expected CapacityExceededError"),
/// }
/// ```
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemEncodeBufError {
    /// Buffer capacity was exceeded during encoding.
    ///
    /// Occurs when trying to write more bytes than the buffer's capacity.
    /// This should never happen if `MemBytesRequired` was calculated correctly.
    #[error("CapacityExceededError")]
    CapacityExceededError,
}

/// Errors that can occur during encoding operations.
///
/// All variants ensure that the source data is zeroized before the error is returned.
///
/// # Error Handling Invariant
///
/// **Critical:** Even when encoding fails, the source value is zeroized. This prevents
/// plaintext from leaking in error paths.
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemEncodeBuf, MemEncode, MemBytesRequired};
///
/// let mut value = vec![1u8, 2, 3, 4, 5];
/// let mut buf = MemEncodeBuf::new(2); // Too small!
///
/// let result = value.drain_into(&mut buf);
///
/// assert!(result.is_err());
/// // Source is zeroized even though encoding failed
/// assert!(value.iter().all(|&b| b == 0));
/// ```
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemEncodeError {
    /// Size calculation overflowed during encoding.
    #[error("OverflowError: {0}")]
    OverflowError(#[from] OverflowError),

    /// Buffer operation failed during encoding.
    #[error("MemEncodeBufError: {0}")]
    MemEncodeBufError(#[from] MemEncodeBufError),

    /// Test-only error for simulating encode failures.
    ///
    /// Available only with `test_utils` feature enabled.
    #[cfg(any(test, feature = "test_utils"))]
    #[error("MemDecodeTestBreaker(IntentionalEncodeError)")]
    IntentionalEncodeError,
}
