// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for memalloc.

use thiserror::Error;

/// Error type for `AllockedVec` operations.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AllockedVecError {
    /// Attempted to reserve capacity on an already-sealed vector.
    #[error("Vector is already sealed and cannot be resized")]
    AlreadySealed,

    /// Integer overflow when computing new length.
    ///
    /// This error is practically impossible to encounter in normal usage,
    /// as it would require a vector with length approaching `isize::MAX`.
    /// It exists as a defensive check for integer overflow safety.
    #[error("Integer overflow: total length would exceed usize::MAX")]
    Overflow,

    /// Attempted to push beyond the vector's capacity.
    #[error("Capacity exceeded: cannot push beyond sealed capacity")]
    CapacityExceeded,
}
