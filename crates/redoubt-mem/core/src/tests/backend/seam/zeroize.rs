// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends write zeros over exactly the range they were given.

use std::vec;
use std::vec::Vec;

use redoubt_asm::Backend;
use rstest::rstest;

use crate::zeroize::zeroize_with_backend;

const GUARD: usize = 32;

/// A byte for every position, never zero: a stray zero written outside the
/// range cannot land on one that was already there.
fn pattern(at: usize) -> u8 {
    ((at.wrapping_mul(131) ^ (at >> 8) ^ 0x97) as u8) | 1
}

macro_rules! zeroizes {
    ($($name:ident: $t:ty),* $(,)?) => {
        $(
            #[rstest]
            #[case::rust(Backend::Rust)]
            #[case::auto(Backend::Auto)]
            fn $name(#[case] backend: Backend) {
                const OF: usize = 257;

                let mut held: Vec<$t> = vec![<$t>::MAX; OF + 2];

                // SAFETY: `held` is two elements longer than what is written,
                // and every byte zero is a value of the width.
                unsafe { zeroize_with_backend(backend, held.as_mut_ptr().add(1), OF) };

                assert!(held[1..=OF].iter().all(|element| *element == 0), "{} elements of {}", OF, stringify!($t));
                assert_eq!(held[0], <$t>::MAX, "wrote before the range");
                assert_eq!(held[OF + 1], <$t>::MAX, "wrote past the range");
            }
        )*
    };
}

zeroizes! {
    test_zeroizes_bytes: u8,
    test_zeroizes_sixteen_bit_words: u16,
    test_zeroizes_thirty_two_bit_words: u32,
    test_zeroizes_sixty_four_bit_words: u64,
    test_zeroizes_hundred_and_twenty_eight_bit_words: u128,
    test_zeroizes_pointer_sized_words: usize,
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroizes_exactly_its_range_at_every_length_and_alignment(#[case] backend: Backend) {
    for offset in 0..16 {
        for of in 0..=1024 {
            let was: Vec<u8> = (0..GUARD + offset + of + GUARD).map(pattern).collect();
            let mut held = was.clone();
            let from = GUARD + offset;

            // SAFETY: the range starts inside `held` and ends `GUARD` bytes
            // before its end.
            unsafe { zeroize_with_backend(backend, held.as_mut_ptr().add(from), of) };

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

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroizes_nothing_for_a_count_of_zero(#[case] backend: Backend) {
    let mut held = [0x9E_u8; 4];

    // SAFETY: zero elements are written.
    unsafe { zeroize_with_backend(backend, held.as_mut_ptr(), 0) };

    assert_eq!(held, [0x9E; 4]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroizes_nothing_for_a_type_of_no_size(#[case] backend: Backend) {
    let mut held = [(); 8];

    // SAFETY: a zero-sized type, where every pointer is valid for zero bytes.
    unsafe { zeroize_with_backend(backend, held.as_mut_ptr(), 8) };

    assert_eq!(held.len(), 8);
}
