// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for Redoubt crates.
//!
//! ## License
//!
//! GPL-3.0-only

#[cfg(test)]
mod tests;

mod permutations;
mod subprocess;

pub use permutations::{apply_permutation, index_permutations};
pub use subprocess::run_test_as_subprocess;
