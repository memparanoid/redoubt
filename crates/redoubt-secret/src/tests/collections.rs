// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_util::is_vec_fully_zeroized;
use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel};

use crate::collections::move_vec;
use crate::traits::MemMove;

/// Macro to test array MemMove for all type implementations
macro_rules! test_array_mem_move {
    ($($t:ty, $test_name:ident, $val:expr),* $(,)?) => {
        $(
            #[test]
            fn $test_name() {
                let mut src = [$val; 32];
                let mut dst = [<$t>::default(); 32];

                <[$t; 32]>::mem_move(&mut src, &mut dst);

                assert_eq!(dst[0], $val);
                // Verify source is fully zeroized
                assert!(src.iter().all(|b| *b == <$t>::default()));
            }
        )*
    };
}

test_array_mem_move!(
    u8,
    test_array_mem_move_u8,
    0xAB,
    u16,
    test_array_mem_move_u16,
    0xABCD,
    u32,
    test_array_mem_move_u32,
    0xABCD_EF01,
    u64,
    test_array_mem_move_u64,
    0xABCD_EF01_2345_6789,
    u128,
    test_array_mem_move_u128,
    0xABCD_EF01_2345_6789_ABCD_EF01_2345_6789,
    usize,
    test_array_mem_move_usize,
    0xABCD,
    i8,
    test_array_mem_move_i8,
    -42,
    i16,
    test_array_mem_move_i16,
    -1234,
    i32,
    test_array_mem_move_i32,
    -123456,
    i64,
    test_array_mem_move_i64,
    -123456789,
    i128,
    test_array_mem_move_i128,
    -123456789123456789,
    isize,
    test_array_mem_move_isize,
    -5678,
    f32,
    test_array_mem_move_f32,
    3.14159,
    f64,
    test_array_mem_move_f64,
    2.718281828,
    bool,
    test_array_mem_move_bool,
    true,
);

/// Macro to test Vec MemMove for all type implementations
macro_rules! test_vec_mem_move {
    ($($t:ty, $test_name:ident, $val:expr),* $(,)?) => {
        $(
            #[test]
            fn $test_name() {
                let mut src = vec![$val, $val, $val, $val];
                let mut dst = Vec::new();

                Vec::<$t>::mem_move(&mut src, &mut dst);

                assert_eq!(dst.len(), 4);
                assert_eq!(dst[0], $val);
                assert!(src.is_empty());
            }
        )*
    };
}

test_vec_mem_move!(
    u8,
    test_vec_mem_move_u8,
    0xDE,
    u16,
    test_vec_mem_move_u16,
    0xDEAD,
    u32,
    test_vec_mem_move_u32,
    0xDEAD_BEEF,
    u64,
    test_vec_mem_move_u64,
    0xDEAD_BEEF_CAFE_BABE,
    u128,
    test_vec_mem_move_u128,
    0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0,
    usize,
    test_vec_mem_move_usize,
    0xDEAD,
    i8,
    test_vec_mem_move_i8,
    -99,
    i16,
    test_vec_mem_move_i16,
    -9999,
    i32,
    test_vec_mem_move_i32,
    -999999,
    i64,
    test_vec_mem_move_i64,
    -999999999,
    i128,
    test_vec_mem_move_i128,
    -999999999999999999,
    isize,
    test_vec_mem_move_isize,
    -8888,
    f32,
    test_vec_mem_move_f32,
    1.234,
    f64,
    test_vec_mem_move_f64,
    5.678901234,
    bool,
    test_vec_mem_move_bool,
    false,
);

/// Test that `move_vec` zeroizes destination before reserve.
///
/// Uses MutByte wrappers with external mutable references to verify
/// that dst.fast_zeroize() is called before reserve_exact.
///
/// Test cases:
/// - Sanity check: verify Vec drop does NOT zeroize MutByte references
/// - src.len() < dst.capacity() (no reserve needed)
/// - src.len() > dst.capacity() (reserve needed)
/// - src.len() == dst.capacity() (boundary case)
#[test]
fn test_move_vec_zeroizes_before_reserve() {
    #[derive(RedoubtZero)]
    struct MutByte<'a> {
        inner: &'a mut u8,
        __sentinel: ZeroizeOnDropSentinel,
    }

    impl<'a> MutByte<'a> {
        fn new(inner: &'a mut u8) -> Self {
            Self {
                inner,
                __sentinel: ZeroizeOnDropSentinel::default(),
            }
        }
    }

    // Case: Sanity Check
    // We MUST verify that dropping Vec<MutByte> does NOT zeroize the referenced values.
    // If drop DID zeroize, our subsequent test cases would be invalid because we couldn't
    // distinguish between zeroization from `move_vec` calling `dst.fast_zeroize()` vs
    // zeroization from `drop(dst)`.
    {
        let mut a = 1u8;
        let mut b = 2u8;

        {
            let vec = vec![MutByte::new(&mut a), MutByte::new(&mut b)];
            drop(vec);
        }

        // Verify that drop did NOT zeroize the external values
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    // Case 1: src.len() < dst.capacity()
    {
        let mut a = 1u8;
        let mut b = 2u8;

        let mut dst = vec![MutByte::new(&mut a), MutByte::new(&mut b)];
        let mut c = 3u8;
        let mut src = vec![MutByte::new(&mut c)];

        move_vec(&mut src, &mut dst);

        assert_eq!(*dst[0].inner, 3);
        drop(dst); // Drop before checking a, b

        assert_eq!(a, 0); // dst was zeroized
        assert_eq!(b, 0);
    }

    // Case 2: src.len() > dst.capacity()
    {
        let mut a = 1u8;
        let mut b = 2u8;

        let mut dst = vec![MutByte::new(&mut a), MutByte::new(&mut b)];

        let mut c = 3u8;
        let mut d = 4u8;
        let mut e = 5u8;
        let mut src = vec![
            MutByte::new(&mut c),
            MutByte::new(&mut d),
            MutByte::new(&mut e),
        ];

        move_vec(&mut src, &mut dst);

        assert_eq!(*dst[0].inner, 3);
        assert_eq!(*dst[2].inner, 5);
        drop(dst); // Drop before checking a, b

        assert_eq!(a, 0); // dst was zeroized BEFORE reserve
        assert_eq!(b, 0);
    }

    // Case 3: src.len() == dst.capacity()
    {
        let mut a = 1u8;
        let mut b = 2u8;

        let mut dst = vec![MutByte::new(&mut a), MutByte::new(&mut b)];

        let mut c = 3u8;
        let mut d = 4u8;
        let mut src = vec![MutByte::new(&mut c), MutByte::new(&mut d)];

        move_vec(&mut src, &mut dst);

        assert_eq!(*dst[0].inner, 3);
        assert_eq!(*dst[1].inner, 4);
        drop(dst); // Drop before checking a, b

        assert_eq!(a, 0);
        assert_eq!(b, 0);
    }
}

// =============================================================================
// RedoubtVec MemMove
// =============================================================================

/// Test `MemMove` for `RedoubtVec`.
///
/// This test is simpler than `test_move_vec_zeroizes_before_reserve` because
/// `RedoubtVec::grow_to()` already guarantees no leaks during growth by design
/// (temp → zeroize old → realloc → move back → zeroize temp). The exhaustive
/// testing of spare capacity zeroization is done in `redoubt-alloc` where the
/// invariant is established.
#[test]
fn test_redoubt_vec_mem_move() {
    use redoubt_alloc::RedoubtVec;
    use redoubt_zero::ZeroizationProbe;

    let mut src = RedoubtVec::new();
    let mut data = vec![0xAB_u8, 0xCD, 0xEF];
    src.drain_slice(&mut data);
    assert!(data.is_zeroized());

    let mut dst = RedoubtVec::new();

    RedoubtVec::<u8>::mem_move(&mut src, &mut dst);

    // dst should have the data
    assert_eq!(dst.len(), 3);
    assert_eq!(dst[0], 0xAB);
    assert_eq!(dst[1], 0xCD);
    assert_eq!(dst[2], 0xEF);

    // src should be empty and zeroized
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());
}

// =============================================================================
// RedoubtString MemMove
// =============================================================================

/// Test `MemMove` for `RedoubtString`.
///
/// This test is simpler than `test_move_vec_zeroizes_before_reserve` because
/// `RedoubtString::grow_to()` already guarantees no leaks during growth by design
/// (temp → zeroize old → realloc → move back → zeroize temp). The exhaustive
/// testing of spare capacity zeroization is done in `redoubt-alloc` where the
/// invariant is established.
#[test]
fn test_redoubt_string_mem_move() {
    use redoubt_alloc::RedoubtString;
    use redoubt_zero::ZeroizationProbe;

    let mut src = RedoubtString::new();
    src.copy_from_str("secret password 123");

    let mut dst = RedoubtString::new();

    RedoubtString::mem_move(&mut src, &mut dst);

    // dst should have the data
    assert_eq!(dst.as_str(), "secret password 123");
    assert_eq!(dst.len(), 19);

    // src should be empty and zeroized
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());
    assert!(src.is_zeroized());
}

// =============================================================================
// Vec<T> MemMove
// =============================================================================

/// Test move_vec with is_vec_fully_zeroized to verify spare capacity is cleared
#[test]
fn test_move_vec_u8_fully_zeroized() {
    let mut src = vec![0xAB_u8; 10];
    let mut dst = vec![0xFF_u8; 5];

    // dst has spare capacity with potentially dirty data
    dst.truncate(3);

    // Before move, dst is NOT fully zeroized
    assert!(!is_vec_fully_zeroized(&dst));

    move_vec(&mut src, &mut dst);

    // After move, src should be empty and fully zeroized
    assert!(src.is_empty());
    assert!(is_vec_fully_zeroized(&src));

    // dst now contains the data
    assert_eq!(dst.len(), 10);
    assert_eq!(dst[0], 0xAB);
}
