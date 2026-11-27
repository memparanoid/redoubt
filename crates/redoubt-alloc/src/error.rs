// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for redoubt-alloc.

use core::fmt;

/// Error type for `AllockedVec` operations.
#[derive(Debug, Eq, PartialEq)]
pub enum AllockedVecError {
    /// Attempted to reserve capacity on an already-sealed vector.
    AlreadySealed,

    /// Integer overflow when computing new length.
    ///
    /// This error is practically impossible to encounter in normal usage,
    /// as it would require a vector with length approaching `isize::MAX`.
    /// It exists as a defensive check for integer overflow safety.
    Overflow,

    /// Attempted to push beyond the vector's capacity.
    CapacityExceeded,
}

impl fmt::Display for AllockedVecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySealed => f.write_str("the vector is sealed, and its capacity is fixed"),
            Self::Overflow => f.write_str("the length would be past usize::MAX"),
            Self::CapacityExceeded => f.write_str("the vector is full: its capacity is sealed"),
        }
    }
}

impl core::error::Error for AllockedVecError {}
