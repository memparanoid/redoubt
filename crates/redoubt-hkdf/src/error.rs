// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

/// HKDF error
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// Requested output length exceeds maximum (255 * HashLen)
    #[error("requested output length exceeds maximum (255 * HashLen)")]
    OutputTooLong,
}
