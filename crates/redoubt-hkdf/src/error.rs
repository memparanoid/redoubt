// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The one way a derivation refuses.

use thiserror::Error;

/// What a derivation answers when it will not do what it was asked.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// More output than the counter has blocks for.
    #[error("requested output length exceeds maximum (255 * HashLen)")]
    OutputTooLong,
}
