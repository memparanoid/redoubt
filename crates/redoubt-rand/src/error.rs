// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

/// Errors that can occur when generating random data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EntropyError {
    /// System entropy source is unavailable or failed to generate random data.
    #[error("EntropyNotAvailable")]
    EntropyNotAvailable,

    /// A failure a test injected.
    ///
    /// Its own variant so that a test asserting an injected failure cannot be
    /// satisfied by a real one.
    #[cfg(any(test, feature = "test-utils"))]
    #[error("a test behaviour refused to give entropy")]
    Injected,
}
