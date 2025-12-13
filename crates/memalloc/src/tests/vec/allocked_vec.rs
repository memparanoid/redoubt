// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::is_vec_fully_zeroized;
use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::allocked_vec::{AllockedVec, AllockedVecBehaviour};
use crate::error::AllockedVecError;

#[test]
fn test_allocked_vec_zeroization_on_drop() {
    let vec = AllockedVec::<u8>::default();
    vec.assert_zeroize_on_drop();
}

#[test]
fn test_allocked_vec_default() {
    let vec: AllockedVec<u8> = AllockedVec::default();

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);

    assert!(vec.is_empty());
    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());
}

#[test]
fn test_allocked_vec_with_capacity_seals_allocked_vec() {
    let vec: AllockedVec<u8> = AllockedVec::with_capacity(10);

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 10);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    // Already sealed - cannot reserve again
    let mut vec = vec;
    let result = vec.reserve_exact(20);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::AlreadySealed)));
}

#[test]
fn test_allocked_vec_reserve_exact_seals_vector() {
    let mut vec: AllockedVec<u8> = AllockedVec::default();

    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());

    // First reserve succeeds
    vec.reserve_exact(5).expect("Failed to reserve_exact");
    assert_eq!(vec.capacity(), 5);

    // Vec is not zeroized since `has_been_sealed` is true after reserve_exact.
    assert!(!vec.is_zeroized());

    // Second reserve fails
    let result = vec.reserve_exact(10);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::AlreadySealed)));
}

#[test]
fn test_allocked_vec_push_within_capacity() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), &[1, 2, 3]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_push_exceeds_capacity() {
    let mut vec = AllockedVec::with_capacity(2);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    // Exceeding capacity fails
    let result = vec.push(3u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Vector data is preserved (not zeroized)
    assert_eq!(vec.as_slice(), &[1, 2]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_drain_from_success() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    let mut data = vec![1u8, 2, 3, 4, 5];

    assert_eq!(vec.len(), 0);

    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);

    // Source should be zeroized
    assert!(data.iter().all(|&x| x == 0));

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_drain_from_exceeds_capacity() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    let mut data = vec![1u8, 2, 3, 4, 5];

    // Exceeding capacity fails
    let result = vec.drain_from(&mut data);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Vec remains empty, source data is not modified
    assert_eq!(vec.len(), 0);
    assert_eq!(data, [1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true (even though len=0).
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_drain_from_partial_fill() {
    let mut vec = AllockedVec::with_capacity(10);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    let mut data = vec![3u8, 4, 5];
    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_as_slice_and_as_mut_slice() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    assert_eq!(vec.as_slice(), &[1, 2]);

    vec.as_mut_slice()[0] = 42;
    assert_eq!(vec.as_slice(), &[42, 2]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_deref_to_slice() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    // Deref allows slice methods
    assert_eq!(vec[0], 1);
    assert_eq!(vec[1], 2);
    assert_eq!(vec.len(), 2);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_debug_snapshot() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    let snapshot = format!("{:?}", vec);
    insta::assert_snapshot!(snapshot);
}

#[test]
fn test_allocked_vec_zeroize_on_drop() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());

    vec.assert_zeroize_on_drop();
}

#[test]
fn test_allocked_vec_realloc_with_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

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

    // Vec is still not zeroized since `has_been_sealed` is true and no realloc happened.
    assert!(!vec.is_zeroized());

    // Realloc with smaller capacity - should also be no-op
    vec.realloc_with_capacity(3);
    // Vec has shrinked
    assert_eq!(vec.capacity(), 3);
    assert_eq!(vec.as_slice(), [1, 2]);

    // Vec is still not zeroized since `has_been_sealed` is true and no realloc happened.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_realloc_with_zeroizes_old_allocation() {
    let mut vec = AllockedVec::with_capacity(2);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

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

    // Vec is not zeroized since new vec has `has_been_sealed` true after realloc.
    assert!(!vec.is_zeroized());

    vec.push(3u8).expect("Failed to vec.push(3)");
    vec.push(4u8).expect("Failed to vec.push(4)");
    vec.push(5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1u8, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_realloc_with_capacity_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");

    // Realloc with same capacity - should be no-op
    vec.realloc_with_capacity(5);

    assert_eq!(vec.capacity(), 5);
    assert_eq!(vec.as_slice(), [1, 2]);

    // Vec is still not zeroized since `has_been_sealed` is true and no realloc happened.
    assert!(!vec.is_zeroized());

    // Realloc with smaller capacity - should also be no-op
    vec.realloc_with_capacity(3);
    // Vec has shrinked
    assert_eq!(vec.capacity(), 3);
    assert_eq!(vec.as_slice(), [1, 2]);

    // Vec is still not zeroized since `has_been_sealed` is true and no realloc happened.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_realloc_with_capacity_preserves_len() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");
    vec.push(4u8).expect("Failed to vec.push(4)");
    vec.push(5u8).expect("Failed to vec.push(5)");

    vec.realloc_with_capacity(10);

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);

    // Vec is not zeroized since new vec has `has_been_sealed` true after realloc.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_realloc_with_capacity_ok() {
    let mut vec = AllockedVec::with_capacity(0);

    // Vec is not zeroized since `has_been_sealed` is true (even with capacity 0).
    assert!(!vec.is_zeroized());

    vec.realloc_with_capacity(5);

    // Vec is not zeroized since new vec has `has_been_sealed` true after realloc.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to vec.push(1)");
    vec.push(2u8).expect("Failed to vec.push(2)");
    vec.push(3u8).expect("Failed to vec.push(3)");
    vec.push(4u8).expect("Failed to vec.push(4)");
    vec.push(5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_fill_with_default_empty_vec() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    assert_eq!(vec.len(), 0);

    vec.fill_with_default();

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), [0, 0, 0, 0, 0]);

    // Vec is not zeroized since `has_been_sealed` is true (even though all elements are 0).
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_fill_with_default_partial_vec() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1).expect("push failed");
    vec.push(2).expect("push failed");

    assert_eq!(vec.len(), 2);

    vec.fill_with_default();

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), [1, 2, 0, 0, 0]);

    // Vec is not zeroized since `has_been_sealed` is true and contains non-zero data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_fill_with_default_full_vec() {
    let mut vec = AllockedVec::<u8>::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1).expect("push failed");
    vec.push(2).expect("push failed");
    vec.push(3).expect("push failed");

    assert_eq!(vec.len(), 3);

    vec.fill_with_default();

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), [1, 2, 3]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_behaviour_fail_at_push() {
    let mut vec = AllockedVec::with_capacity(10);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

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

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_behaviour_fail_at_drain_from() {
    let mut vec = AllockedVec::with_capacity(10);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

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

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_truncate_zeroizes_removed_elements() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

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

    // Vec is not zeroized since `has_been_sealed` is true (even though all elements are 0).
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_as_mut_ptr_write_single_byte() {
    let mut vec = AllockedVec::<u8>::with_capacity(1);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(0u8).expect("Failed to push initial byte");

    let ptr = vec.as_mut_ptr();

    unsafe {
        *ptr = 0x42;
    }

    assert_eq!(vec.as_slice(), &[0x42]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_as_capacity_slice_returns_full_capacity() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to push");
    vec.push(2u8).expect("Failed to push");

    // len is 2, but capacity is 5
    assert_eq!(vec.len(), 2);
    assert_eq!(vec.capacity(), 5);

    // as_capacity_slice returns full capacity (zeroed by with_capacity)
    let slice = vec.as_capacity_slice();
    assert_eq!(slice.len(), 5);
    assert_eq!(&slice[..2], &[1, 2]);
    // Spare capacity is zeroed
    assert_eq!(&slice[2..], &[0, 0, 0]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_capacity_is_zeroed_on_creation() {
    // Test that spare capacity is zeroed when using reserve_exact
    let mut vec = AllockedVec::<u8>::new();

    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());

    vec.reserve_exact(100).expect("Failed to reserve");

    // Vec is not zeroized since `has_been_sealed` is true after reserve_exact.
    assert!(!vec.is_zeroized());

    // All capacity should be zeroed
    let slice = vec.as_capacity_slice();
    assert_eq!(slice.len(), 100);
    assert!(slice.iter().all(|&b| b == 0));

    // Vec is not zeroized since `has_been_sealed` is true (even though all elements are 0).
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_as_capacity_mut_slice_allows_writing_beyond_len() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to push");
    vec.push(2u8).expect("Failed to push");

    // Write beyond len (but within capacity)
    let slice = vec.as_capacity_mut_slice();
    slice[2] = 3;
    slice[3] = 4;
    slice[4] = 5;

    // len unchanged, but data is written
    assert_eq!(vec.len(), 2);

    // Verify via as_capacity_slice
    let slice = vec.as_capacity_slice();
    assert_eq!(slice, &[1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_set_len_can_shrink() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to push(1)");
    vec.push(2u8).expect("Failed to push(2)");
    vec.push(3u8).expect("Failed to push(3)");

    // SAFETY: 1 <= len, elements at 0..1 are initialized
    unsafe { vec.set_len(1) };

    assert_eq!(vec.len(), 1);
    assert_eq!(vec.as_slice(), &[1]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_set_len_can_grow_within_capacity() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(1u8).expect("Failed to push(1)");
    vec.push(2u8).expect("Failed to push(2)");

    // Write to spare capacity first
    vec.as_capacity_mut_slice()[2] = 3;
    vec.as_capacity_mut_slice()[3] = 4;

    // SAFETY: 4 <= capacity, elements at 0..4 are initialized
    unsafe { vec.set_len(4) };

    assert_eq!(vec.len(), 4);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}
