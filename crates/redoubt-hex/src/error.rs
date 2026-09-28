// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The ways an encoding or a decoding does not happen.

/// What comes back instead of the bytes or the digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    /// The digits are not an even count, so they spell no whole byte.
    #[error("odd number of hex digits")]
    OddLength,

    /// The destination is not as long as what is written into it.
    #[error("destination of the wrong length")]
    WrongDestination,

    /// A character is not a hex digit. Which one is not said, and the
    /// destination is left all zeros.
    #[error("not hex")]
    NotHex,
}
