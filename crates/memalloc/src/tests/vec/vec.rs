// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::is_vec_fully_zeroized;
use memzer::AssertZeroizeOnDrop;

use crate::vec::{AllockedVec, AllockedVecBehaviour, AllockedVecError};

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
    let result = vec.reserve_exact(20);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::AlreadySealed)));
}

#[test]
fn test_reserve_exact_seals_vector() {
    let mut vec: AllockedVec<u8> = AllockedVec::new();

    // First reserve succeeds
    vec.reserve_exact(5).expect("Failed to reserve_exact");
    assert_eq!(vec.capacity(), 5);

    // Second reserve fails
    let result = vec.reserve_exact(10);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::AlreadySealed)));
}

#[test]
fn test_push_within_capacity() {
    let mut vec = AllockedVec::with_capacity(3);

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), &[1, 2, 3]);
}

#[test]
fn test_push_exceeds_capacity() {
    let mut vec = AllockedVec::with_capacity(2);

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    // Exceeding capacity fails
    let result = vec.push(3u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Vector data is preserved (not zeroized)
    assert_eq!(vec.as_slice(), &[1, 2]);
}

#[test]
fn test_drain_from_success() {
    let mut vec = AllockedVec::with_capacity(5);
    let mut data = vec![1u8, 2, 3, 4, 5];

    vec.drain_from(&mut data).expect("Failed to drain_from");

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
    let result = vec.drain_from(&mut data);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Vec remains empty, source data is not modified
    assert_eq!(vec.len(), 0);
    assert_eq!(data, [1, 2, 3, 4, 5]);
}

#[test]
fn test_drain_from_partial_fill() {
    let mut vec = AllockedVec::with_capacity(10);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    let mut data = vec![3u8, 4, 5];
    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_as_slice_and_as_mut_slice() {
    let mut vec = AllockedVec::with_capacity(3);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    assert_eq!(vec.as_slice(), &[1, 2]);

    vec.as_mut_slice()[0] = 42;
    assert_eq!(vec.as_slice(), &[42, 2]);
}

#[test]
fn test_deref_to_slice() {
    let mut vec = AllockedVec::with_capacity(3);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

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
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    let snapshot = format!("{:?}", vec);
    insta::assert_snapshot!(snapshot);
}

#[test]
fn test_zeroize_on_drop() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");

    vec.assert_zeroize_on_drop();
}

#[test]
fn test_realloc_with_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    let mut hook_has_been_called = false;

    // Realloc with same capacity - should be no-op
    vec.realloc_with(5, |_| {
        hook_has_been_called = true;
    });

    assert!(!hook_has_been_called);
    assert_eq!(vec.capacity(), 5);
    assert_eq!(vec.as_slice(), [1, 2]);

    // Realloc with smaller capacity - should also be no-op
    vec.realloc_with(3, |_| {
        hook_has_been_called = true;
    });

    assert!(!hook_has_been_called);
    assert_eq!(vec.capacity(), 5);
    assert_eq!(vec.as_slice(), [1, 2]);
}

#[test]
fn test_realloc_with_zeroizes_old_allocation() {
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

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

    vec.push(3u8).expect("Failed to vec.push(3)");
    vec.push(4u8).expect("Failed to vec.push(4)");
    vec.push(5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1u8, 2, 3, 4, 5]);
}

#[test]
fn test_realloc_with_capacity_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    // Realloc with same capacity - should be no-op
    vec.realloc_with_capacity(5);

    assert_eq!(vec.capacity(), 5);
    assert_eq!(vec.as_slice(), [1, 2]);

    // Realloc with smaller capacity - should also be no-op
    vec.realloc_with_capacity(3);

    assert_eq!(vec.capacity(), 5);
    assert_eq!(vec.as_slice(), [1, 2]);
}

#[test]
fn test_realloc_with_capacity_ok() {
    let mut vec = AllockedVec::with_capacity(0);
    vec.realloc_with_capacity(5);

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");
    vec.push(4u8).expect("Failed to vec.push(4)");
    vec.push(5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);
}

#[test]
fn test_behaviour_fail_at_push() {
    let mut vec = AllockedVec::with_capacity(10);
    vec.change_behaviour(AllockedVecBehaviour::FailAtPush);

    let result = vec.push(1u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Behaviour is sticky - still fails
    let result = vec.push(2u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Reset behaviour
    vec.change_behaviour(AllockedVecBehaviour::None);

    // Now push should work
    vec.push(1u8).expect("Failed to vec.push(1)");
    assert_eq!(vec.as_slice(), &[1]);
}

#[test]
fn test_behaviour_fail_at_drain_from() {
    let mut vec = AllockedVec::with_capacity(10);
    let mut data = vec![1u8, 2, 3];

    vec.change_behaviour(AllockedVecBehaviour::FailAtDrainFrom);

    let result = vec.drain_from(&mut data);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Data should not be modified
    assert_eq!(data, [1, 2, 3]);

    // Behaviour is sticky - still fails
    let result = vec.drain_from(&mut data);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Reset behaviour
    vec.change_behaviour(AllockedVecBehaviour::None);

    // Now drain should work
    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.as_slice(), &[1, 2, 3]);
    assert!(data.iter().all(|&x| x == 0));
}

#[test]
fn test_truncate_zeroizes_removed_elements() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(0u8).expect("Failed to push");
    vec.push(0u8).expect("Failed to push");
    vec.push(0u8).expect("Failed to push");
    vec.push(1u8).expect("Failed to push");
    vec.push(2u8).expect("Failed to push");

    vec.__unsafe_expose_inner_for_tests(|inner| {
        assert!(!is_vec_fully_zeroized(inner));
    });

    vec.truncate(3);

    vec.__unsafe_expose_inner_for_tests(|inner| {
        assert!(is_vec_fully_zeroized(inner));
    });
}
