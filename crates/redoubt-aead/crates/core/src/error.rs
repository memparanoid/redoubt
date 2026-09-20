// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The ways an AEAD operation does not finish.

/// What comes back instead of the work being done.
///
/// One enum for every operation in this crate's traits, entropy included.
/// A backend that failed to find randomness and one handed a key of the wrong
/// width are the same kind of news to the caller — the operation did not
/// happen — and splitting them across two error types buys a second `From`
/// impl at every call site and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    /// The tag is not the one that sealed this ciphertext.
    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,

    /// The key is not the width this backend takes.
    #[error("invalid key size")]
    InvalidKeySize,

    /// The nonce is not the width this backend takes.
    #[error("invalid nonce size")]
    InvalidNonceSize,

    /// The tag is not the width this backend takes.
    #[error("invalid tag size")]
    InvalidTagSize,

    /// The machine has no randomness to give.
    #[error("entropy not available")]
    EntropyNotAvailable,

    /// A failure a test injected.
    ///
    /// Its own variant so that a case asserting an injected failure cannot be
    /// satisfied by a real one, and gated so that nothing which ships can
    /// answer with it.
    #[cfg(any(test, feature = "test-utils"))]
    #[error("a test behaviour refused this operation")]
    Injected,
}
