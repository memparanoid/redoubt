// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt;

/// Errors that can occur when generating random data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// System entropy source is unavailable or failed to generate random data.
    EntropyNotAvailable,

    /// A failure a test injected.
    ///
    /// Its own variant so that a test asserting an injected failure cannot be
    /// satisfied by a real one.
    #[cfg(any(test, feature = "test-utils"))]
    Injected,
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyNotAvailable => f.write_str("the system gave no entropy"),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Injected => f.write_str("a test behaviour refused to give entropy"),
        }
    }
}

impl core::error::Error for EntropyError {}
