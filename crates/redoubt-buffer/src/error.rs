// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for redoubt-buffer.
use alloc::boxed::Box;
use thiserror::Error;

/// Errors from page syscalls.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum PageError {
    #[error("mmap failed")]
    Create,

    #[error("mlock failed")]
    Lock,

    #[error("mprotect(PROT_NONE) failed")]
    Protect,

    #[error("mprotect(PROT_WRITE) failed")]
    Unprotect,

    #[error("madvise(MADV_DONTDUMP) failed")]
    Madvise,
    #[error("a buffer of {len} bytes does not fit a page of {capacity}")]
    TooWide { len: usize, capacity: usize },
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

    /// What a callback handed back instead of finishing.
    ///
    /// Transparent, so the caller reads its own error rather than this crate's
    /// name wrapped around it, and `source` reaches the thing itself.
    #[error(transparent)]
    CallbackError(Box<dyn core::error::Error + Send + Sync + 'static>),

    /// A mutex was poisoned.
    #[error("mutex poisoned")]
    MutexPoisoned,
}

impl BufferError {
    /// Boxes an error a callback returned, so it travels as this one.
    pub fn callback_error<E: core::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::CallbackError(Box::new(e))
    }
}
