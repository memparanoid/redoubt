// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Storage backend implementations

#[cfg(any(test, feature = "std"))]
pub mod std;

#[cfg(any(test, not(feature = "std")))]
pub mod portable;

#[cfg(feature = "std")]
pub use std::open;

#[cfg(not(feature = "std"))]
pub use portable::open;

#[cfg(all(feature = "internal-forensics", feature = "std"))]
pub use std::reset;

#[cfg(all(feature = "internal-forensics", not(feature = "std")))]
pub use portable::reset;
