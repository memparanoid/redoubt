// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Exhaustive tests for BufferError.

use core::error::Error;

use crate::error::{BufferError, PageError};

/// What a callback hands back, carrying a message no variant of
/// `BufferError` has, so reading it back proves it came through.
#[derive(Debug, thiserror::Error)]
#[error("the caller had its own reason")]
struct Callers;

/// A callback's error that already had a cause when it was handed over.
#[derive(Debug, thiserror::Error)]
#[error("the caller failed at work of its own")]
struct CallersWithCause(#[source] Callers);

// =============================================================================
// callback_error()
// =============================================================================

#[test]
fn test_callback_error_displays_what_the_callback_returned() {
    let error = BufferError::callback_error(Callers);

    assert_eq!(error.to_string(), Callers.to_string());
}

/// The wrapper is transparent, so what a chain walker reaches past it is
/// the callback's own cause and not the callback's error again.
#[test]
fn test_callback_error_sources_the_cause_the_callback_error_had() {
    let error = BufferError::callback_error(CallersWithCause(Callers));

    let source = error.source().expect("the callback error had a cause");

    assert_eq!(source.to_string(), Callers.to_string());
}

#[test]
fn test_callback_error_sources_nothing_where_the_callback_error_had_no_cause() {
    let error = BufferError::callback_error(Callers);

    assert!(error.source().is_none());
}

// =============================================================================
// Page
// =============================================================================

#[test]
fn test_a_page_error_sources_the_page_error() {
    let error = BufferError::from(PageError::Lock);

    let source = error.source().expect("a page error has a source");

    assert_eq!(source.to_string(), PageError::Lock.to_string());
}
