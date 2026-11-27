// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The one way a derivation refuses.

use core::fmt;

use crate::consts::MAX_OUTPUT_SIZE;

/// What a derivation answers when it will not do what it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// More output than the counter has blocks for.
    OutputTooLong,
}

impl fmt::Display for HkdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong => write!(
                f,
                "more output was asked for than the {MAX_OUTPUT_SIZE} bytes a derivation gives"
            ),
        }
    }
}

impl core::error::Error for HkdfError {}
