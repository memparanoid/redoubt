// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That the copy copies, for every width a secret is actually held in.
//!
//! # Why the types and not only the bytes
//!
//! The assembly moves bytes and knows nothing about `T`. What it can get
//! wrong is the arithmetic on this side: a count in elements multiplied by a
//! size, a zero-sized type whose pointers are allowed to be dangling, a
//! length of zero. Those are one line each and each has been a bug in
//! somebody's `memcpy` wrapper.
//!
//! So every integer width is here, and so are the three shapes a caller
//! actually has: an array, a slice of one, and a `Vec`.
//!
//! The neighbours are checked as well as the bytes. A copy that wrote one
//! element too many would pass every assertion about what landed and fail the
//! ones about what did not.

use std::vec;
use std::vec::Vec;

use crate::copy_nonoverlapping;

/// A value of `T` from an index, with every byte different from its
/// neighbours'.
///
/// Multiplying by an odd constant and folding in a higher byte means no two
/// indices agree and no byte of one element repeats in the next, so a copy
/// that landed one element off is a copy that fails.
macro_rules! pattern {
    ($t:ty, $at:expr) => {
        (($at as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5A) as $t
    };
}

/// The same copy through every width, with the count in elements.
macro_rules! moves {
    ($($name:ident: $t:ty),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                const OF: usize = 257;

                let from: Vec<$t> = (0..OF).map(|at| pattern!($t, at)).collect();
                let mut into: Vec<$t> = vec![0; OF + 2];

                // Offset by one, so that a copy which forgot the destination
                // pointer and wrote from the start would land on the guard.
                // SAFETY: different allocations, and `into` is two elements
                // longer than what is written into it.
                unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr().add(1), OF) };

                assert_eq!(&into[1..=OF], &from[..], "{} elements of {}", OF, stringify!($t));
                assert_eq!(into[0], 0, "wrote before the destination");
                assert_eq!(into[OF + 1], 0, "wrote past the destination");
            }
        )*
    };
}

moves! {
    test_moves_bytes: u8,
    test_moves_sixteen_bit_words: u16,
    test_moves_thirty_two_bit_words: u32,
    test_moves_sixty_four_bit_words: u64,
    test_moves_hundred_and_twenty_eight_bit_words: u128,
    test_moves_pointer_sized_words: usize,
    test_moves_signed_bytes: i8,
    test_moves_signed_sixty_four_bit_words: i64,
}

/// One element of each width, which is the shortest copy that is not nothing.
///
/// Every path in the assembly is picked by length, and the shortest ones are
/// the tails nobody exercises by accident.
macro_rules! moves_one {
    ($($name:ident: $t:ty),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let from: $t = pattern!($t, 7_usize);
                let mut into: $t = 0;

                // SAFETY: two distinct locals of the same type.
                unsafe { copy_nonoverlapping(&raw const from, &raw mut into, 1) };

                assert_eq!(into, from, "one {}", stringify!($t));
            }
        )*
    };
}

moves_one! {
    test_moves_one_byte: u8,
    test_moves_one_sixteen_bit_word: u16,
    test_moves_one_thirty_two_bit_word: u32,
    test_moves_one_sixty_four_bit_word: u64,
    test_moves_one_hundred_and_twenty_eight_bit_word: u128,
    test_moves_one_pointer_sized_word: usize,
}

/// Every length from nothing to past the point where the assembly changes
/// paths twice.
///
/// `0..=1024` covers the general-register path, the vector path, the loop and
/// the bulk path, and every tail between them.
#[test]
fn test_moves_every_length_up_to_a_kilobyte() {
    let from: Vec<u8> = (0..1024).map(|at| pattern!(u8, at)).collect();

    for of in 0..=from.len() {
        let mut into = vec![0xA5_u8; from.len() + 1];

        // SAFETY: different allocations, and `into` is longer than `of`.
        unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), of) };

        assert_eq!(&into[..of], &from[..of], "{of} bytes");
        assert!(
            into[of..].iter().all(|byte| *byte == 0xA5),
            "wrote past {of} bytes"
        );
    }
}

/// Nothing, which has to be a copy that writes nothing rather than a copy of
/// one.
#[test]
fn test_moves_nothing_for_a_count_of_zero() {
    let from = [0x9E_u8; 4];
    let mut into = [0_u8; 4];

    // SAFETY: different allocations, and zero elements are read and written.
    unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), 0) };

    assert_eq!(into, [0; 4]);
}

/// And nothing for a type of no size, whose pointers may be dangling and must
/// therefore never be handed to the assembly.
#[test]
fn test_moves_nothing_for_a_type_of_no_size() {
    let from = [(); 8];
    let mut into = [(); 8];

    // SAFETY: a zero-sized type, where every pointer is valid for zero bytes.
    unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), 8) };

    assert_eq!(into.len(), 8);
}

// ============================================================================
// The shapes a caller has
// ============================================================================

/// A slice into the middle of another, which is the shape a secret arrives in.
#[test]
fn test_moves_a_slice_out_of_the_middle_of_one() {
    let from: Vec<u8> = (0..256).map(|at| pattern!(u8, at)).collect();
    let taking = &from[37..37 + 64];
    let mut into = vec![0_u8; 64];

    // SAFETY: different allocations, and `into` is as long as `taking`.
    unsafe { copy_nonoverlapping(taking.as_ptr(), into.as_mut_ptr(), taking.len()) };

    assert_eq!(&into[..], taking);
}

/// A `Vec` into another `Vec`, whole.
#[test]
fn test_moves_a_vec_into_another() {
    let from: Vec<u64> = (0..300).map(|at| pattern!(u64, at)).collect();
    let mut into: Vec<u64> = vec![0; from.len()];

    // SAFETY: different allocations of the same length.
    unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };

    assert_eq!(into, from);
}

/// And back out of it, so that a round trip through the routine is the
/// identity rather than merely something that does not crash.
#[test]
fn test_a_round_trip_leaves_the_value_as_it_was() {
    let first: Vec<u128> = (0..64).map(|at| pattern!(u128, at)).collect();
    let mut middle: Vec<u128> = vec![0; first.len()];
    let mut last: Vec<u128> = vec![0; first.len()];

    // SAFETY: three distinct allocations of the same length.
    unsafe {
        copy_nonoverlapping(first.as_ptr(), middle.as_mut_ptr(), first.len());
        copy_nonoverlapping(middle.as_ptr(), last.as_mut_ptr(), middle.len());
    }

    assert_eq!(last, first);
}

/// A struct, which is what a secret is once it has a name.
#[test]
fn test_moves_a_struct_of_mixed_widths() {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Key {
        tag: u8,
        counter: u64,
        bytes: [u8; 32],
        length: usize,
    }

    let from = Key {
        tag: 0x9E,
        counter: 0x4117_C35A_F02B_8867,
        bytes: core::array::from_fn(|at| pattern!(u8, at)),
        length: 32,
    };
    let mut into = Key::default();

    // SAFETY: two distinct locals of the same type.
    unsafe { copy_nonoverlapping(&raw const from, &raw mut into, 1) };

    assert_eq!(into, from);
}

/// A slice of those, because an array of structs is the arithmetic most
/// likely to be off: the element size is neither a power of two nor a byte.
#[test]
fn test_moves_a_slice_of_structs() {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Odd {
        tag: u8,
        counter: u32,
        rest: [u8; 3],
    }

    let from: Vec<Odd> = (0..101_u32)
        .map(|at| Odd {
            tag: pattern!(u8, at),
            counter: at,
            rest: [
                pattern!(u8, at + 1),
                pattern!(u8, at + 2),
                pattern!(u8, at + 3),
            ],
        })
        .collect();
    let mut into: Vec<Odd> = vec![Odd::default(); from.len() + 1];

    // SAFETY: different allocations, and `into` is one element longer.
    unsafe { copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };

    assert_eq!(&into[..from.len()], &from[..]);
    assert_eq!(
        into[from.len()],
        Odd::default(),
        "wrote past the destination"
    );
}

// ============================================================================
// Where it lands
// ============================================================================

/// Every alignment of source against destination, at a few lengths.
///
/// The assembly reads and writes unaligned on purpose, and the tails are
/// where an off-by-one lives. Sixty-four of each covers a whole cache line of
/// starting positions.
#[test]
fn test_moves_at_every_alignment() {
    let from: Vec<u8> = (0..192).map(|at| pattern!(u8, at)).collect();

    for of in [1_usize, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        for at in 0..64 {
            for to in 0..64 {
                let mut into = vec![0xA5_u8; 192];

                // SAFETY: different allocations, and both offsets leave room
                // for `of` bytes in a buffer of 192.
                unsafe {
                    copy_nonoverlapping(from.as_ptr().add(at), into.as_mut_ptr().add(to), of);
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
