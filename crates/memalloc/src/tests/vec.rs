// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::is_vec_fully_zeroized;
use memzer::AssertZeroizeOnDrop;

use crate::{AllockedVec, AllockedVecError};

#[test]
fn test_new_is_empty() {
    let vec: AllockedVec<u8> = AllockedVec::new();
    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);
    assert!(vec.is_empty());
}

#[test]
fn test_with_capacity_creates_sealed() {
    let vec: AllockedVec<u8> = AllockedVec::with_capacity(10);
    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 10);

    // Already sealed - cannot reserve again
    let mut vec = vec;
    assert!(matches!(
        vec.reserve_exact(20),
        Err(AllockedVecError::AlreadySealed)
    ));
}

#[test]
fn test_reserve_exact_seals_vector() {
    let mut vec: AllockedVec<u8> = AllockedVec::new();

    // First reserve succeeds
    assert!(vec.reserve_exact(5).is_ok());
    assert_eq!(vec.capacity(), 5);

    // Second reserve fails
    assert!(matches!(
        vec.reserve_exact(10),
        Err(AllockedVecError::AlreadySealed)
    ));
}

#[test]
fn test_push_within_capacity() {
    let mut vec = AllockedVec::with_capacity(3);

    assert!(vec.push(1u8).is_ok());
    assert!(vec.push(2u8).is_ok());
    assert!(vec.push(3u8).is_ok());

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), &[1, 2, 3]);
}

#[test]
fn test_push_exceeds_capacity() {
    let mut vec = AllockedVec::with_capacity(2);

    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    // Exceeding capacity fails
    assert!(matches!(
        vec.push(3u8),
        Err(AllockedVecError::CapacityExceeded)
    ));

    // Vector data is preserved (not zeroized)
    assert_eq!(vec.as_slice(), &[1, 2]);
}

#[test]
fn test_drain_from_success() {
    let mut vec = AllockedVec::with_capacity(5);
    let mut data = vec![1u8, 2, 3, 4, 5];

    assert!(vec.drain_from(&mut data).is_ok());

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);

    // Source should be zeroized
    assert!(data.iter().all(|&x| x == 0));
}

#[test]
fn test_drain_from_exceeds_capacity() {
    let mut vec = AllockedVec::with_capacity(3);
    let mut data = vec![1u8, 2, 3, 4, 5];

    // Exceeding capacity fails
    assert!(matches!(
        vec.drain_from(&mut data),
        Err(AllockedVecError::CapacityExceeded)
    ));

    // Vec remains empty, source data is preserved (no partial drain)
    assert_eq!(vec.len(), 0);
    assert_eq!(data, vec![1u8, 2, 3, 4, 5]);
}

#[test]
fn test_drain_from_partial_fill() {
    let mut vec = AllockedVec::with_capacity(10);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    let mut data = vec![3u8, 4, 5];
    assert!(vec.drain_from(&mut data).is_ok());

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_as_slice_and_as_mut_slice() {
    let mut vec = AllockedVec::with_capacity(3);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    assert_eq!(vec.as_slice(), &[1, 2]);

    vec.as_mut_slice()[0] = 42;
    assert_eq!(vec.as_slice(), &[42, 2]);
}

#[test]
fn test_deref_to_slice() {
    let mut vec = AllockedVec::with_capacity(3);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    // Deref allows slice methods
    assert_eq!(vec[0], 1);
    assert_eq!(vec[1], 2);
    assert_eq!(vec.len(), 2);
}

#[test]
fn test_default() {
    let vec: AllockedVec<u8> = AllockedVec::default();
    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);
}

#[test]
fn test_debug_snapshot() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    let snapshot = format!("{:?}", vec);
    insta::assert_snapshot!(snapshot);
}

#[test]
fn test_zeroize_on_drop() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();
    vec.push(3u8).unwrap();

    vec.assert_zeroize_on_drop();
}

#[test]
fn test_realloc_with_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    let mut hook_has_been_called = false;

    vec.realloc_with(2, |_| {
        hook_has_been_called = true;
    });

    assert!(!hook_has_been_called);
    assert_eq!(vec.as_slice(), [1, 2]);
}

#[test]
fn test_realloc_with_zeroizes_old_allocation() {
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();

    let result = vec.push(3u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    let mut hook_has_been_called = false;

    vec.realloc_with(5, |old_allocked_vec| {
        old_allocked_vec.__unsafe_expose_inner_for_tests(|vec| {
            hook_has_been_called = true;
            assert!(is_vec_fully_zeroized(vec));
        });
    });

    assert!(hook_has_been_called);

    vec.push(3u8).unwrap();
    vec.push(4u8).unwrap();
    vec.push(5u8).unwrap();

    assert_eq!(vec.as_slice(), [1u8, 2, 3, 4, 5]);
}

#[test]
fn test_realloc_with_capacity_ok() {
    let mut vec = AllockedVec::with_capacity(0);
    vec.realloc_with_capacity(5);

    vec.push(1u8).unwrap();
    vec.push(2u8).unwrap();
    vec.push(3u8).unwrap();
    vec.push(4u8).unwrap();
    vec.push(5u8).unwrap();

    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);
}
