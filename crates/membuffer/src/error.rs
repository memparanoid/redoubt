// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for membuffer.
use thiserror::Error;

/// Errors from memory protection syscalls (mlock, mprotect).
/// Used with abort_from_error for exhaustive matching.
#[derive(Debug, Error)]
pub enum PageProtectionError {
    #[error("failed to lock page")]
    LockFailed,

    #[error("failed to protect page")]
    ProtectionFailed,

    #[error("failed to unprotect page")]
    UnprotectionFailed,
}

/// All page-related errors.
#[derive(Debug, Error)]
pub enum PageError {
    #[error("failed to create page")]
    CreationFailed,

    #[error("{0}")]
    Protection(#[from] PageProtectionError),
}

#[derive(Debug, Error)]
pub enum ProtectedBufferError {
    #[error("PageError: {0}")]
    Page(#[from] PageError),

    #[error("page is no longer available")]
    PageNoLongerAvailable,

    #[error("callback error: {0:?}")]
    CallbackError(Box<dyn core::fmt::Debug + Send + Sync + 'static>),
}

impl ProtectedBufferError {
    pub fn callback_error<E: core::fmt::Debug + Send + Sync + 'static>(e: E) -> Self {
        Self::CallbackError(Box::new(e))
    }
}
