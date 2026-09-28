// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends copy exactly the bytes they were given, and nothing
//! beside them.

mod bounds;

use std::vec;
use std::vec::Vec;

use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::copy_nonoverlapping;

fn pattern(at: usize) -> u8 {
    ((at as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5A) as u8
}

// ============================================================================
// copy_nonoverlapping
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_moves_every_length_up_to_a_kilobyte(#[case] backend: Backend) {
    let from: Vec<u8> = (0..1024).map(pattern).collect();

    for of in 0..=from.len() {
        let mut into = vec![0xA5_u8; from.len() + 1];

        // SAFETY: different allocations, and `into` is longer than `of`.
        unsafe { copy_nonoverlapping(backend, from.as_ptr(), into.as_mut_ptr(), of) };

        assert_eq!(&into[..of], &from[..of], "{of} bytes");
        assert!(
            into[of..].iter().all(|byte| *byte == 0xA5),
            "wrote past {of} bytes"
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_moves_at_every_alignment(#[case] backend: Backend) {
    let from: Vec<u8> = (0..192).map(pattern).collect();

    for of in [1_usize, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        for at in 0..64 {
            for to in 0..64 {
                let mut into = vec![0xA5_u8; 192];

                // SAFETY: different allocations, and both offsets leave room
                // for `of` bytes in a buffer of 192.
                unsafe {
                    copy_nonoverlapping(
                        backend,
                        from.as_ptr().add(at),
                        into.as_mut_ptr().add(to),
                        of,
                    );
                }

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
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_moves_a_slice_out_of_the_middle_of_one(#[case] backend: Backend) {
    let from: Vec<u8> = (0..256).map(pattern).collect();
    let taking = &from[37..37 + 64];
    let mut into = vec![0_u8; 64];

    // SAFETY: different allocations, and `into` is as long as `taking`.
    unsafe { copy_nonoverlapping(backend, taking.as_ptr(), into.as_mut_ptr(), taking.len()) };

    assert_eq!(&into[..], taking);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_copy_nonoverlapping_twice_leaves_the_bytes_as_they_were(#[case] backend: Backend) {
    let first: Vec<u8> = (0..1024).map(pattern).collect();
    let mut middle = vec![0_u8; first.len()];
    let mut last = vec![0_u8; first.len()];

    // SAFETY: three distinct allocations of the same length.
    unsafe {
        copy_nonoverlapping(backend, first.as_ptr(), middle.as_mut_ptr(), first.len());
        copy_nonoverlapping(backend, middle.as_ptr(), last.as_mut_ptr(), middle.len());
    }

    assert_eq!(last, first);
}
