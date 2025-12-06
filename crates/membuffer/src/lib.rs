// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! membuffer - Secure memory buffers
//!
//! Provides two buffer implementations:
//! - `PortableBuffer`: Standard allocation, works everywhere (no-op security)
//! - `ProtectedBuffer`: Unix-only with mmap, mlock, mprotect (best-effort)

#![cfg_attr(feature = "no_std", no_std)]

#[cfg(test)]
mod tests;

mod portable;
#[cfg(unix)]
mod protected;

pub use portable::PortableBuffer;

#[cfg(unix)]
pub use protected::ProtectedBuffer;
