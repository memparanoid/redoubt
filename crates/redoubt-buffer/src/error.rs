// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for redoubt-buffer.
use alloc::boxed::Box;
use thiserror::Error;

/// Errors from page syscalls.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum PageError {
    #[error("mmap failed")]
    Create = 0,

    #[error("mlock failed")]
    Lock = 1,

    #[error("mprotect(PROT_NONE) failed")]
    Protect = 2,

    #[error("mprotect(PROT_WRITE) failed")]
    Unprotect = 3,

    #[error("madvise(MADV_DONTDUMP) failed")]
    Madvise = 4,
}

/// Errors that can occur when working with buffers.
#[derive(Debug, Error)]
pub enum BufferError {
    /// An error occurred during a page operation.
    #[error("PageError: {0}")]
    Page(#[from] PageError),

    /// The page is no longer available.
    #[error("page is no longer available")]
    PageNoLongerAvailable,

    /// An error occurred in a callback function.
    #[error("callback error: {0:?}")]
    CallbackError(Box<dyn core::fmt::Debug + Send + Sync + 'static>),

    /// A mutex was poisoned.
    #[error("mutex poisoned")]
    MutexPoisoned,
}

impl BufferError {
    /// Creates a CallbackError from any Debug + Send + Sync error.
    pub fn callback_error<E: core::fmt::Debug + Send + Sync + 'static>(e: E) -> Self {
        Self::CallbackError(Box::new(e))
    }
}
