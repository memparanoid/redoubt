// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

/// Errors that can occur when generating random data.
#[derive(Debug, Error)]
pub enum EntropyError {
    /// System entropy source is unavailable or failed to generate random data.
    #[error("EntropyNotAvailable")]
    EntropyNotAvailable,
}
