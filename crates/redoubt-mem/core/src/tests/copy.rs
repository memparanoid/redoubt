// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::copy::copy_nonoverlapping_using;
use crate::copy_nonoverlapping;

// ============================================================================
// copy_nonoverlapping
// ============================================================================

proptest! {
    #[test]
    fn test_copy_nonoverlapping_leaves_the_destination_equal_to_the_source(
        from in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut into: Vec<u8> = vec![0; from.len()];

        // SAFETY: two distinct allocations of the same length.
        unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };

        prop_assert_eq!(into, from);
    }
}

// ============================================================================
// copy_nonoverlapping_using
// ============================================================================

/// Twelve bytes with its padding, a size that is not a power of two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
struct Odd {
    tag: u8,
    counter: u32,
    rest: [u8; 3],
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_using_counts_in_elements(#[case] backend: Backend) {
    let from: Vec<Odd> = (0..101_u32)
        .map(|at| Odd {
            tag: at as u8,
            counter: at.wrapping_mul(0x9E37_79B9),
            rest: [at as u8 ^ 0x5A, at as u8 ^ 0xA5, at as u8 ^ 0x3C],
        })
        .collect();
    let mut into: Vec<Odd> = vec![Odd::default(); from.len() + 1];

    // SAFETY: different allocations, and `into` is one element longer.
    unsafe { copy_nonoverlapping_using(backend, from.as_ptr(), into.as_mut_ptr(), from.len()) };

    assert_eq!(&into[..from.len()], &from[..]);
    assert_eq!(
        into[from.len()],
        Odd::default(),
        "wrote past the destination"
    );
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_using_moves_nothing_for_a_count_of_zero(#[case] backend: Backend) {
    let from = [0x9E_u8; 4];
    let mut into = [0_u8; 4];

    // SAFETY: different allocations, and zero elements are read and written.
    unsafe { copy_nonoverlapping_using(backend, from.as_ptr(), into.as_mut_ptr(), 0) };

    assert_eq!(into, [0; 4]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_using_moves_nothing_for_a_type_of_no_size(#[case] backend: Backend) {
    let from = [(); 8];
    let mut into = [(); 8];

    // SAFETY: a zero-sized type, where every pointer is valid for zero bytes.
    unsafe { copy_nonoverlapping_using(backend, from.as_ptr(), into.as_mut_ptr(), 8) };

    assert_eq!(into.len(), 8);
}
