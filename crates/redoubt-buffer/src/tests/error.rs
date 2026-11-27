// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Exhaustive tests for BufferError.

use core::error::Error;
use core::fmt;

use rstest::rstest;

use crate::error::{BufferError, PageError};

/// What a callback hands back, carrying a message no variant of
/// `BufferError` has, so reading it back proves it came through.
#[derive(Debug)]
struct Callers;

impl fmt::Display for Callers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the caller had its own reason")
    }
}

impl Error for Callers {}

/// A callback's error that already had a cause when it was handed over.
#[derive(Debug)]
struct CallersWithCause(Callers);

impl fmt::Display for CallersWithCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the caller failed at work of its own")
    }
}

impl Error for CallersWithCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

// =============================================================================
// PageError: Display
// =============================================================================

#[rstest]
#[case::create(PageError::Create, "the page could not be mapped")]
#[case::lock(PageError::Lock, "the page could not be locked in memory")]
#[case::protect(PageError::Protect, "the page could not be closed to every access")]
#[case::unprotect(PageError::Unprotect, "the page could not be opened for writing")]
#[case::madvise(PageError::Madvise, "the page could not be left out of core dumps")]
#[case::too_wide(
    PageError::TooWide { len: 4097, capacity: 4096 },
    "a buffer of 4097 bytes does not fit a page of 4096"
)]
fn test_page_error_says_what_happened(#[case] error: PageError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// =============================================================================
// PageError: Error::source
// =============================================================================

#[rstest]
#[case::create(PageError::Create)]
#[case::lock(PageError::Lock)]
#[case::protect(PageError::Protect)]
#[case::unprotect(PageError::Unprotect)]
#[case::madvise(PageError::Madvise)]
#[case::too_wide(PageError::TooWide { len: 4097, capacity: 4096 })]
fn test_page_error_source_returns_none(#[case] error: PageError) {
    assert!(error.source().is_none());
}

// =============================================================================
// BufferError: Display
// =============================================================================

#[rstest]
#[case::page(BufferError::Page(PageError::Lock), "a page operation failed")]
#[case::page_no_longer_available(
    BufferError::PageNoLongerAvailable,
    "the page is no longer available"
)]
fn test_buffer_error_says_what_happened(#[case] error: BufferError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// =============================================================================
// BufferError: Error::source
// =============================================================================

#[test]
fn test_buffer_error_source_returns_none_for_a_page_no_longer_available() {
    assert!(BufferError::PageNoLongerAvailable.source().is_none());
}

// =============================================================================
// callback_error()
// =============================================================================

#[test]
fn test_callback_error_displays_what_the_callback_returned() {
    let error = BufferError::callback_error(Callers);

    assert_eq!(error.to_string(), "the caller had its own reason");
}

/// The wrapper is transparent, so what a chain walker reaches past it is
/// the callback's own cause and not the callback's error again.
#[test]
fn test_callback_error_sources_the_cause_the_callback_error_had()
-> Result<(), Box<dyn std::error::Error>> {
    let error = BufferError::callback_error(CallersWithCause(Callers));

    let source = error.source().ok_or("the callback error had no cause")?;

    assert_eq!(source.to_string(), "the caller had its own reason");

    Ok(())
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
fn test_a_page_error_sources_the_page_error() -> Result<(), Box<dyn std::error::Error>> {
    let error = BufferError::from(PageError::Lock);

    let source = error.source().ok_or("the page error had no source")?;

    assert_eq!(source.to_string(), "the page could not be locked in memory");

    Ok(())
}
