// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One file here for each file there, and the same shape of directory around
//! them, so that finding what tests a function is reading its path with
//! `tests/` in front of it.

#[cfg(target_os = "linux")]
mod analysis;

#[cfg(target_os = "linux")]
mod errors;

#[cfg(target_os = "linux")]
mod forensics;

#[cfg(target_os = "linux")]
mod macros;

#[cfg(target_os = "linux")]
mod spiller;
