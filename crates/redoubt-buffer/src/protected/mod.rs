// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ProtectedBuffer - Unix protected memory buffer
//!
//! Uses mmap for allocation, mlock to prevent swapping,
//! and mprotect to control access (best-effort).
//!
//! # Security Model
//!
//! The buffer maintains two invariants for sensitive data:
//! 1. **Protected**: Page has PROT_NONE (no read/write access)
//! 2. **Zeroized**: Page contents are all zeros
//!
//! On disposal, we guarantee at least one of these holds.
//! If both protections fail, the process aborts.
//!
//! # Error Handling Strategy
//!
//! When mprotect fails during open/open_mut:
//! - We track protection state internally (not via syscalls)
//! - Zeroization uses fork() best-effort: child attempts write,
//!   if page is protected it crashes (safe), if unprotected it zeros (safe)
//! - This avoids relying on mprotect() return value in dispose()
//!   which could lie if seccomp blocked the syscall

mod abort;
mod buffer;
mod enums;

pub use buffer::ProtectedBuffer;
pub use enums::ProtectionStrategy;

// Test-only exports
#[cfg(test)]
pub(crate) use abort::AbortCode;
#[cfg(test)]
pub(crate) use enums::TryCreateStage;
