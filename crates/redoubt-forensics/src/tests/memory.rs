// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Which mappings are read, and how a needle is counted inside one.
//!
//! Both are decided on bytes alone, so both can be asserted without a process
//! to look at — which is what makes them worth asserting at all. What a caller
//! concludes from a count of zero rests on the second of these.

use crate::analysis::memory::{region, within};

// ============================================================================
// region
// ============================================================================

/// The bounds of a mapping that can be written to. Writable and not merely
/// readable, because what is left behind is left behind by writing.
#[test]
fn test_region_returns_the_bounds_of_a_writable_mapping() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0"),
        Some((0x7f8e_1c00_0000, 0x7f8e_1c02_1000)),
    );
}

/// Executable is code, and code holds what a compiler put there.
#[test]
fn test_region_returns_nothing_for_a_mapping_that_is_code() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 r-xp 00000000 00:00 0 [vdso]"),
        None
    );
}

/// A file mapped in read-only is that file, and reading the binary back is
/// seconds per sweep for nothing.
#[test]
fn test_region_returns_nothing_for_a_file_mapped_read_only() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 r--p 00000000 08:01 131 /usr/lib/libc.so.6"),
        None,
    );
}

/// A page with no permissions at all is a guarded secret at rest, and it is
/// skipped on purpose.
///
/// That is where a key is *meant* to be. Sweeping it would make every sweep
/// find the secret in its own home, and every absence a caller asked about
/// would come back a positive.
#[test]
fn test_region_returns_nothing_for_a_page_protected_to_nothing() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 ---p 00000000 00:00 0"),
        None
    );
}

/// And one open for writing alone, which is what a guarded page looks like
/// from outside while it is being read through. Skipped for the same reason.
#[test]
fn test_region_returns_nothing_for_a_write_only_page() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 -w-p 00000000 00:00 0"),
        None
    );
}

#[test]
fn test_region_returns_nothing_for_a_line_that_is_not_one() {
    assert_eq!(region(b""), None);
}

// ============================================================================
// within
// ============================================================================

/// Every occurrence and not the first: a secret in two places has to read as
/// two.
#[test]
fn test_within_counts_every_occurrence() {
    assert_eq!(within(b"--ab--ab--", b"ab", false), 2);
}

#[test]
fn test_within_counts_a_needle_read_backwards() {
    assert_eq!(within(b"--ba--", b"ab", true), 1);
}

/// A window shorter than the needle holds none of it, which is what the last
/// read of a mapping looks like.
#[test]
fn test_within_counts_nothing_in_less_than_a_needle() {
    assert_eq!(within(b"a", b"ab", false), 0);
}
