// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for membuffer.
use thiserror::Error;

/// Errors from page syscalls.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum PageError {
    #[error("mmap failed")]
    CreationFailed = 0,

    #[error("mlock failed")]
    LockFailed = 1,

    #[error("mprotect(PROT_NONE) failed")]
    ProtectionFailed = 2,

    #[error("mprotect(PROT_WRITE) failed")]
    UnprotectionFailed = 3,
}

#[derive(Debug, Error)]
pub enum BufferError {
    #[error("PageError: {0}")]
    Page(#[from] PageError),

    #[error("page is no longer available")]
    PageNoLongerAvailable,

    #[error("callback error: {0:?}")]
    CallbackError(Box<dyn core::fmt::Debug + Send + Sync + 'static>),

    #[error("mutex poisoned")]
    MutexPoisoned,
}

impl BufferError {
    pub fn callback_error<E: core::fmt::Debug + Send + Sync + 'static>(e: E) -> Self {
        Self::CallbackError(Box::new(e))
    }
}
