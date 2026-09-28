// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::zeroize;
use crate::zeroize::zeroize_using;

// ============================================================================
// zeroize
// ============================================================================

proptest! {
    #[test]
    fn test_zeroize_leaves_every_byte_zero(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut held: Vec<u8> = bytes;

        // SAFETY: the vec is writable for its own length, and every byte zero
        // is a `u8`.
        unsafe { zeroize(held.as_mut_ptr(), held.len()) };

        prop_assert!(held.iter().all(|byte| *byte == 0));
    }
}

// ============================================================================
// zeroize_using
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroize_using_counts_in_elements(#[case] backend: Backend) {
    const OF: usize = 257;

    let mut held: Vec<u128> = vec![u128::MAX; OF + 2];

    // SAFETY: `held` is two elements longer than what is written, and every
    // byte zero is a `u128`.
    unsafe { zeroize_using(backend, held.as_mut_ptr().add(1), OF) };

    assert!(held[1..=OF].iter().all(|element| *element == 0));
    assert_eq!(held[0], u128::MAX, "wrote before the range");
    assert_eq!(held[OF + 1], u128::MAX, "wrote past the range");
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroize_using_writes_nothing_for_a_count_of_zero(#[case] backend: Backend) {
    let mut held = [0x9E_u8; 4];

    // SAFETY: zero elements are written.
    unsafe { zeroize_using(backend, held.as_mut_ptr(), 0) };

    assert_eq!(held, [0x9E; 4]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_zeroize_using_writes_nothing_for_a_type_of_no_size(#[case] backend: Backend) {
    let mut held = [(); 8];

    // SAFETY: a zero-sized type, where every pointer is valid for zero bytes.
    unsafe { zeroize_using(backend, held.as_mut_ptr(), 8) };

    assert_eq!(held.len(), 8);
}
