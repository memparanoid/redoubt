// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ============================================================================
// Page::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it maps and zeroes an empty page."]
fn test_making_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::lock
// ============================================================================

#[test]
#[ignore = "Reads no secret: it asks the kernel to keep the page in memory."]
fn test_locking_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::mark_dontdump
// ============================================================================

#[test]
#[ignore = "Reads no secret: it asks the kernel to leave the page out of dumps."]
fn test_marking_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::protect
// ============================================================================

#[test]
#[ignore = "Reads no secret: it changes the page's protection."]
fn test_protecting_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::unprotect
// ============================================================================

#[test]
#[ignore = "Reads no secret: it changes the page's protection."]
fn test_unprotecting_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_reading_a_page_length_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::as_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_viewing_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::as_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands out a reference."]
fn test_viewing_a_page_mutably_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::zeroize
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes zeros."]
fn test_zeroizing_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::munlock
// ============================================================================

#[test]
#[ignore = "Reads no secret: it asks the kernel to let the page be swapped."]
fn test_unlocking_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Page::munmap
// ============================================================================

#[test]
#[ignore = "Reads no secret: it unmaps the page."]
fn test_unmapping_a_page_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Drop for Page
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes zeros over the page and unmaps it."]
fn test_dropping_a_page_leaves_nothing() {
    // Intentionally empty.
}
