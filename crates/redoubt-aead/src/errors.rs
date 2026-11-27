// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt;

use redoubt_aead_core::AeadCoreError;
use redoubt_rand::EntropyError;

use crate::enums::AeadAlgorithm;

/// What comes back instead of the message being sealed or opened.
///
/// A width that does not fit names the cipher that was measuring. AEGIS-128L
/// and XChaCha20-Poly1305 take different widths, so a caller told only that a
/// key was the wrong size is left to work out which cipher was asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// What the primitive answered.
    Core(AeadCoreError),

    /// No nonce came back, so nothing was sealed with one.
    NonceEntropy(EntropyError),

    /// The key is not the width this algorithm takes.
    KeyWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },

    /// The nonce is not the width this algorithm takes.
    NonceWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },

    /// The tag is not the width this algorithm takes.
    TagWidth {
        /// The cipher that was asked to do the work.
        algorithm: AeadAlgorithm,
        /// The width it takes.
        expected: usize,
        /// The width that arrived.
        given: usize,
    },
}

impl From<AeadCoreError> for AeadError {
    fn from(core_error: AeadCoreError) -> Self {
        Self::Core(core_error)
    }
}

impl From<EntropyError> for AeadError {
    fn from(entropy_error: EntropyError) -> Self {
        Self::NonceEntropy(entropy_error)
    }
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(core_error) => fmt::Display::fmt(core_error, f),
            Self::NonceEntropy(entropy_error) => {
                write!(f, "no nonce could be generated: {entropy_error}")
            }
            Self::KeyWidth {
                algorithm,
                expected,
                given,
            } => write!(
                f,
                "{algorithm:?} seals with a key of {expected} bytes and was handed {given}"
            ),
            Self::NonceWidth {
                algorithm,
                expected,
                given,
            } => write!(
                f,
                "{algorithm:?} seals with a nonce of {expected} bytes and was handed {given}"
            ),
            Self::TagWidth {
                algorithm,
                expected,
                given,
            } => write!(
                f,
                "{algorithm:?} writes a tag of {expected} bytes and was handed {given}"
            ),
        }
    }
}

impl core::error::Error for AeadError {}
