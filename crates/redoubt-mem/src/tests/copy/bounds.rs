// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That the copy stays inside the range it was given, and that it is still a
//! copy when the range is large.
//!
//! # Why a guard page and not a pattern
//!
//! Filling the destination with a sentinel and checking it afterwards catches
//! a write past the end. It catches nothing about a *read* past the end, and a
//! read is what the tails here are most likely to get wrong — every one of
//! them loads from an offset worked out backwards from the length.
//!
//! A page with no permissions on either side turns that into a fault. The
//! source sits flush against the end of a readable page with nothing after it,
//! and flush against the start with nothing before it, so a load of one byte
//! too many is a signal rather than a value nobody checks.
//!
//! The destination is mapped the same way, which is what the sentinel could
//! already have told us — it is here because the two must be tested at the
//! same offsets to be worth anything.

#![cfg(unix)]

use std::vec;
use std::vec::Vec;

use crate::copy_nonoverlapping;

fn pattern(at: usize) -> u8 {
    (at.wrapping_mul(131) ^ (at >> 8) ^ 0x97) as u8
}

/// Three pages, of which only the middle one may be touched.
struct Fenced {
    base: *mut u8,
    page: usize,
}

impl Fenced {
    fn new() -> Self {
        // SAFETY: a fresh anonymous mapping of three pages, unreadable, and
        // then the middle one opened for writing. Nothing else refers to it.
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE);

            assert!(page > 0, "no page size");

            let page = page as usize;

            let base = libc::mmap(
                core::ptr::null_mut(),
                page * 3,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            assert_ne!(base, libc::MAP_FAILED, "no mapping");

            let at = Self {
                base: base.cast(),
                page,
            };

            assert_eq!(
                libc::mprotect(
                    at.base.add(page).cast(),
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                ),
                0,
                "the middle page would not open",
            );

            at
        }
    }

    /// The one page that may be touched.
    fn middle(&self) -> *mut u8 {
        // SAFETY: in bounds of a mapping of three pages.
        unsafe { self.base.add(self.page) }
    }
}

impl Drop for Fenced {
    fn drop(&mut self) {
        // SAFETY: the mapping is this struct's own and nothing else refers to
        // it.
        unsafe { libc::munmap(self.base.cast(), self.page * 3) };
    }
}

/// A copy flush against each end of a page, with no permissions on the other
/// side of it.
///
/// Every length from one byte to a whole page, and both ends of both buffers.
/// A read or a write one byte outside the range is a fault, and a fault here
/// is the test failing in the loudest way there is.
#[test]
fn test_reads_and_writes_nothing_outside_the_range() {
    let from = Fenced::new();
    let into = Fenced::new();
    let page = from.page;

    // SAFETY: the middle page is readable and writable for exactly `page`
    // bytes, and every offset below leaves room for `of` bytes inside it.
    unsafe {
        for at in 0..page {
            from.middle().add(at).write(pattern(at));
        }

        assert_eq!(
            libc::mprotect(from.middle().cast(), page, libc::PROT_READ),
            0,
            "the source would not go read-only",
        );

        for of in 1..=page {
            for flush_start in [false, true] {
                for flush_end in [false, true] {
                    let src = from.middle().add(if flush_start { page - of } else { 0 });
                    let dst = into.middle().add(if flush_end { page - of } else { 0 });

                    copy_nonoverlapping(src, dst, of);

                    assert_eq!(
                        core::slice::from_raw_parts(src, of),
                        core::slice::from_raw_parts(dst, of),
                        "{of} bytes, flush {flush_start}/{flush_end}",
                    );
                }
            }
        }
    }
}

/// Past every threshold the assembly has, and well past the largest of them.
///
/// The paths change at 32, 64 and 512 bytes on `x86_64` and at 64 on
/// `aarch64`, and the last of those hands the work to a string move that the
/// tests above never reach. A step that is not a power of two lands on
/// lengths no boundary is near.
#[test]
fn test_moves_the_large_sizes_and_every_threshold() {
    const MOST: usize = 1 << 18;

    let from: Vec<u8> = (0..MOST + 128).map(pattern).collect();
    let mut into = vec![0xA5_u8; from.len()];

    let thresholds = [
        31_usize, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024,
        1025, 2047, 2048, 2049, 4095, 4096, 4097, MOST,
    ];

    for of in (1025..=MOST).step_by(997).chain(thresholds) {
        for (at, to) in [(0, 0), (1, 31), (63, 1), (17, 49), (33, 33)] {
            into.fill(0xA5);

            // SAFETY: different allocations, and `from` is 128 bytes longer
            // than the largest `of` plus the largest offset.
            unsafe { copy_nonoverlapping(from.as_ptr().add(at), into.as_mut_ptr().add(to), of) };

            assert_eq!(
                &into[to..to + of],
                &from[at..at + of],
                "{of} bytes {at}→{to}"
            );
            assert!(
                into[..to]
                    .iter()
                    .chain(&into[to + of..])
                    .all(|byte| *byte == 0xA5),
                "{of} bytes {at}→{to} wrote outside",
            );
        }
    }
}
