// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The ways an encoding or a decoding does not happen.

use core::fmt;

/// What comes back instead of the bytes or the digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The digits are not an even count, so they spell no whole byte.
    OddLength,

    /// The destination is not as long as what is written into it.
    WrongDestination,

    /// A character is not a hex digit. Which one is not said, and the
    /// destination is left all zeros.
    NotHex,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("an odd number of hex digits spells no whole byte"),
            Self::WrongDestination => {
                f.write_str("the destination is not as long as what is written into it")
            }
            Self::NotHex => f.write_str("a character is not a hex digit"),
        }
    }
}

impl core::error::Error for HexError {}
