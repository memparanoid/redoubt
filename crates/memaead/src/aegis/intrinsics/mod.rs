// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Platform-specific AES intrinsics.

#[cfg(target_arch = "x86_64")]
mod ni;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "x86_64")]
pub use ni::Intrinsics;

#[cfg(target_arch = "aarch64")]
pub use aarch64::Intrinsics;
