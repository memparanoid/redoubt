// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memory forensics tooling for Redoubt.
//!
//! Both modules are deliberately self-contained — one file each, no dependency
//! on the rest of this crate — so they can be copied into another project that
//! needs the same analysis.
//!
//! They are used together. [`dumper`] decides *where* the analysis looks;
//! [`never_free`] decides whether *not finding something there* is evidence of
//! anything.

/// Linux-only: the dump is taken from `/proc/self/maps` and `/proc/self/mem`,
/// which have no equivalent elsewhere. The analysis is meant to run on Linux,
/// natively or through the `Dockerfile` next to this crate.
#[cfg(target_os = "linux")]
pub mod dumper;
pub mod never_free;
