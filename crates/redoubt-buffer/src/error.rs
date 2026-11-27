// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Error types for redoubt-buffer.
use alloc::boxed::Box;
use core::fmt;

/// Errors from page syscalls.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PageError {
    Create,
    Lock,
    Protect,
    Unprotect,
    Madvise,
    TooWide { len: usize, capacity: usize },
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => f.write_str("the page could not be mapped"),
            Self::Lock => f.write_str("the page could not be locked in memory"),
            Self::Protect => f.write_str("the page could not be closed to every access"),
            Self::Unprotect => f.write_str("the page could not be opened for writing"),
            Self::Madvise => f.write_str("the page could not be left out of core dumps"),
            Self::TooWide { len, capacity } => {
                write!(
                    f,
                    "a buffer of {len} bytes does not fit a page of {capacity}"
                )
            }
        }
    }
}

impl core::error::Error for PageError {}

/// Errors that can occur when working with buffers.
#[derive(Debug)]
pub enum BufferError {
    /// An error occurred during a page operation.
    Page(PageError),

    /// The page is no longer available.
    PageNoLongerAvailable,

    /// What a callback handed back instead of finishing.
    ///
    /// Transparent, so the caller reads its own error rather than this crate's
    /// name wrapped around it, and `source` reaches the cause it had.
    CallbackError(Box<dyn core::error::Error + Send + Sync + 'static>),
}

impl BufferError {
    /// Boxes an error a callback returned, so it travels as this one.
    pub fn callback_error<E: core::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::CallbackError(Box::new(e))
    }
}

impl From<PageError> for BufferError {
    fn from(page_error: PageError) -> Self {
        Self::Page(page_error)
    }
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Page(_) => f.write_str("a page operation failed"),
            Self::PageNoLongerAvailable => f.write_str("the page is no longer available"),
            Self::CallbackError(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl core::error::Error for BufferError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Page(page_error) => Some(page_error),
            Self::PageNoLongerAvailable => None,
            Self::CallbackError(error) => error.source(),
        }
    }
}
