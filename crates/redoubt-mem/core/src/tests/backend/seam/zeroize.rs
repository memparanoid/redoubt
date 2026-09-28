// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends write zeros over exactly the range they were given.

use std::vec::Vec;

use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::zeroize;

const GUARD: usize = 32;

/// A byte for every position, never zero: a stray zero written outside the
/// range cannot land on one that was already there.
fn pattern(at: usize) -> u8 {
    ((at.wrapping_mul(131) ^ (at >> 8) ^ 0x97) as u8) | 1
}

// ============================================================================
// zeroize
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroize_writes_zeros_over_exactly_its_range_at_every_length_and_alignment(
    #[case] backend: Backend,
) {
    for offset in 0..16 {
        for of in 0..=1024 {
            let was: Vec<u8> = (0..GUARD + offset + of + GUARD).map(pattern).collect();
            let mut held = was.clone();
            let from = GUARD + offset;

            // SAFETY: the range starts inside `held` and ends `GUARD` bytes
            // before its end.
            unsafe { zeroize(backend, held.as_mut_ptr().add(from), of) };

            for (at, (now, before)) in held.iter().zip(&was).enumerate() {
                let expected = if (from..from + of).contains(&at) {
                    0
                } else {
                    *before
                };

                assert_eq!(*now, expected, "offset {offset}, {of} bytes, byte {at}");
            }
        }
    }
}
