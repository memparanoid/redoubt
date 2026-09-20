// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead_core::AeadError as AeadCoreError;
use redoubt_rand::EntropyError;

use crate::enums::AeadAlgorithm;

/// What comes back instead of the message being sealed or opened.
///
/// A width that does not fit names the cipher that was measuring. AEGIS-128L
/// and XChaCha20-Poly1305 take different widths, so a caller told only that a
/// key was the wrong size is left to work out which cipher was asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    /// What the primitive answered.
    #[error(transparent)]
    Primitive(#[from] AeadCoreError),

    /// No nonce came back, so nothing was sealed with one.
    #[error("the machine gave no randomness to draw a nonce from")]
    NonceEntropy(#[from] EntropyError),

    /// The key is not the width this algorithm takes.
    #[error("{algorithm:?} seals with a key of {expected} bytes and was handed {given}")]
    KeyWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },

    /// The nonce is not the width this algorithm takes.
    #[error("{algorithm:?} seals with a nonce of {expected} bytes and was handed {given}")]
    NonceWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },

    /// The tag is not the width this algorithm takes.
    #[error("{algorithm:?} writes a tag of {expected} bytes and was handed {given}")]
    TagWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },
}

