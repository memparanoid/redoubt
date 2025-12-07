// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for membuffer.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LibcPageError {
    #[error("failed to create page")]
    PageCreationFailed,

    #[error("failed to lock page")]
    LockFailed,

    #[error("failed to protect page")]
    ProtectionFailed,

    #[error("failed to unprotect page")]
    UnprotectionFailed,
}

#[derive(Debug, Error)]
pub enum ProtectedBufferError {
    #[error("LibcPageError: {0}")]
    LibcPage(#[from] LibcPageError),

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
