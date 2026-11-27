// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The ways an AEAD operation does not finish.

use core::fmt;

/// What comes back instead of the work being done.
///
/// One enum for every operation in this crate's traits, entropy included.
/// A backend that failed to find randomness and one handed a key of the wrong
/// width are the same kind of news to the caller — the operation did not
/// happen — and splitting them across two error types buys a second `From`
/// impl at every call site and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadCoreError {
    /// The tag is not the one that sealed this ciphertext.
    AuthenticationFailed,

    /// The key is not the width this backend takes.
    InvalidKeySize,

    /// The nonce is not the width this backend takes.
    InvalidNonceSize,

    /// The tag is not the width this backend takes.
    InvalidTagSize,

    /// The machine has no randomness to give.
    EntropyNotAvailable,

    /// A failure a test injected.
    ///
    /// Its own variant so that a case asserting an injected failure cannot be
    /// satisfied by a real one, and gated so that nothing which ships can
    /// answer with it.
    #[cfg(any(test, feature = "test-utils"))]
    Injected,
}

impl fmt::Display for AeadCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => f.write_str(
                "the tag does not match: the ciphertext was changed, or sealed with another key",
            ),
            Self::InvalidKeySize => f.write_str("the key is not the width this cipher takes"),
            Self::InvalidNonceSize => f.write_str("the nonce is not the width this cipher takes"),
            Self::InvalidTagSize => f.write_str("the tag is not the width this cipher takes"),
            Self::EntropyNotAvailable => f.write_str("the system gave no entropy"),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Injected => f.write_str("a test behaviour refused this operation"),
        }
    }
}

impl core::error::Error for AeadCoreError {}
