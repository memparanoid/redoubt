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

#[cfg(unix)]
mod protected;

#[cfg(unix)]
pub use protected::{ProtectedBuffer, ProtectionStrategy};

mod error;
mod portable;
mod traits;

pub use error::ProtectedBufferError;
pub use portable::PortableBuffer;
pub use traits::Buffer;
