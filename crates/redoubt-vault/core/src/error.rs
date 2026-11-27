// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault error types

use core::fmt;

use redoubt_aead::AeadError;
use redoubt_buffer::BufferError;
use redoubt_codec::{DecodeError, EncodeError, OverflowError};

#[derive(Debug)]
pub enum CipherBoxError {
    Overflow(OverflowError),

    Encode(EncodeError),

    Decode(DecodeError),

    Buffer(BufferError),

    Aead(AeadError),

    /// The CipherBox is in an irrecoverable state due to operation failure.
    ///
    /// This error occurs when a cryptographic operation fails partway through,
    /// leaving some fields decrypted (plaintext exposed in memory). For security,
    /// all exposed plaintext is immediately zeroized before returning this error.
    ///
    /// **The data is permanently lost.** The CipherBox cannot be recovered or
    /// used again after this error. This is intentional: security guarantees
    /// take precedence over data preservation.
    Poisoned,

    /// The CipherBox was intentionally zeroized.
    ///
    /// This error occurs when `fast_zeroize()` was called on the CipherBox,
    /// either explicitly or via drop. Unlike `Poisoned`, this is not an error
    /// condition but an intentional destruction of the encrypted data.
    ///
    /// **The data is permanently gone.** The CipherBox cannot be used after
    /// zeroization.
    Zeroized,

    /// What the failure mode of a derived box answers with, once its counter
    /// reaches the operation it was told to fail on.
    ///
    /// Available only with the `test-utils` feature enabled. A crate that
    /// names a `testing_feature` on its box has to enable it from there.
    #[cfg(any(test, feature = "test-utils"))]
    IntentionalCipherBoxError,
}

impl From<OverflowError> for CipherBoxError {
    fn from(overflow_error: OverflowError) -> Self {
        Self::Overflow(overflow_error)
    }
}

impl From<EncodeError> for CipherBoxError {
    fn from(encode_error: EncodeError) -> Self {
        Self::Encode(encode_error)
    }
}

impl From<DecodeError> for CipherBoxError {
    fn from(decode_error: DecodeError) -> Self {
        Self::Decode(decode_error)
    }
}

impl From<BufferError> for CipherBoxError {
    fn from(buffer_error: BufferError) -> Self {
        Self::Buffer(buffer_error)
    }
}

impl From<AeadError> for CipherBoxError {
    fn from(aead_error: AeadError) -> Self {
        Self::Aead(aead_error)
    }
}

impl fmt::Display for CipherBoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow(overflow_error) => fmt::Display::fmt(overflow_error, f),
            Self::Encode(encode_error) => fmt::Display::fmt(encode_error, f),
            Self::Decode(decode_error) => fmt::Display::fmt(decode_error, f),
            Self::Buffer(buffer_error) => fmt::Display::fmt(buffer_error, f),
            Self::Aead(aead_error) => fmt::Display::fmt(aead_error, f),
            Self::Poisoned => f.write_str(
                "the box is poisoned: an operation failed partway, and the plaintext it had \
                 exposed was zeroized",
            ),
            Self::Zeroized => f.write_str("the box was zeroized, and holds nothing to open"),
            #[cfg(any(test, feature = "test-utils"))]
            Self::IntentionalCipherBoxError => {
                f.write_str("a test behaviour refused this operation on the box")
            }
        }
    }
}

impl core::error::Error for CipherBoxError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Buffer(buffer_error) => core::error::Error::source(buffer_error),
            Self::Overflow(_)
            | Self::Encode(_)
            | Self::Decode(_)
            | Self::Aead(_)
            | Self::Poisoned
            | Self::Zeroized => None,
            #[cfg(any(test, feature = "test-utils"))]
            Self::IntentionalCipherBoxError => None,
        }
    }
}
