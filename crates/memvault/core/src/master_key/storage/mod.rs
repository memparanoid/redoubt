// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Storage backend implementations

#[cfg(any(test, not(feature = "no_std")))]
pub mod std;

#[cfg(any(test, feature = "no_std"))]
pub mod portable;

#[cfg(not(feature = "no_std"))]
pub use std::open;

#[cfg(feature = "no_std")]
pub use portable::open;
