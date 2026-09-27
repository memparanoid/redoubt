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

#[cfg(target_os = "linux")]
mod seccomp;

mod permutations;
mod subprocess;

#[cfg(target_os = "linux")]
pub use seccomp::{block_syscall, is_seccomp_available};

pub use permutations::{apply_permutation, index_permutations};
pub use subprocess::run_test_as_subprocess;
