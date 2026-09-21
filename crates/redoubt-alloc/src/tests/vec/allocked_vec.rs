// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_util::is_vec_fully_zeroized;
use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::allocked_vec::{AllockedVec, AllockedVecBehaviour};
use crate::error::AllockedVecError;

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ ZEROIZATION                                                                ║
// ╚════════════════════════════════════════════════════════════════════════════╝

#[test]
fn test_allocked_vec_is_zeroizable() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(5);

    vec.push(&mut 1u8)?;
    assert!(!vec.is_zeroized());

    vec.fast_zeroize();
    assert!(vec.is_zeroized());

    Ok(())
}

#[test]
fn test_allocked_vec_zeroizes_on_drop() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(5);

    vec.push(&mut 1u8)?;
    assert!(!vec.is_zeroized());

    vec.assert_zeroize_on_drop();

    Ok(())
}

// =============================================================================
// new()
// =============================================================================

// Tested by test_allocked_vec_default (Default impl)

// =============================================================================
// with_capacity()
// =============================================================================

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

// =============================================================================
// reserve_exact()
// =============================================================================

#[test]
fn test_allocked_vec_reserve_exact_seals_vector() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec: AllockedVec<u8> = AllockedVec::default();

    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());

    // First reserve succeeds
    vec.reserve_exact(5)?;
    assert_eq!(vec.capacity(), 5);

    // Vec is not zeroized since `has_been_sealed` is true after reserve_exact.
    assert!(!vec.is_zeroized());

    // Second reserve fails
    let result = vec.reserve_exact(10);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::AlreadySealed)));

    Ok(())
}

#[test]
fn test_allocked_vec_capacity_is_zeroed_on_creation() -> Result<(), Box<dyn std::error::Error>> {
    // Test that spare capacity is zeroed when using reserve_exact
    let mut vec = AllockedVec::<u8>::new();

    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());

    vec.reserve_exact(100)?;

    // Vec is not zeroized since `has_been_sealed` is true after reserve_exact.
    assert!(!vec.is_zeroized());

    // All capacity should be zeroed
    let slice = unsafe { vec.as_capacity_slice() };
    assert_eq!(slice.len(), 100);
    assert!(slice.iter().all(|&b| b == 0));

    // Vec is not zeroized since `has_been_sealed` is true (even though all elements are 0).
    assert!(!vec.is_zeroized());

    Ok(())
}

// =============================================================================
// push()
// =============================================================================

#[test]
fn test_allocked_vec_push_within_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8)?;
    vec.push(&mut 2u8)?;
    vec.push(&mut 3u8)?;

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), &[1, 2, 3]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());

    Ok(())
}

#[test]
fn test_allocked_vec_push_exceeds_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(2);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8)?;
    vec.push(&mut 2u8)?;

    // Exceeding capacity fails
    let result = vec.push(&mut 3u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Vector data is preserved (not zeroized)
    assert_eq!(vec.as_slice(), &[1, 2]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());

    Ok(())
}

#[test]
fn test_allocked_vec_push_empties_what_it_was_handed() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(1);
    let mut one = 7u8;

    vec.push(&mut one)?;

    assert_eq!(vec.as_slice(), &[7]);

    // Assert zeroization!
    assert!(one.is_zeroized());

    Ok(())
}

#[test]
fn test_allocked_vec_push_carries_an_array_whole() -> Result<(), Box<dyn std::error::Error>> {
    let mut vec = AllockedVec::with_capacity(1);
    let mut one = [9u8; 32];

    vec.push(&mut one)?;

    assert_eq!(vec.as_slice(), &[[9u8; 32]]);

    // Assert zeroization!
    assert!(one.is_zeroized());

    Ok(())
}

/// A `T` that owns an allocation crosses by its pointer.
///
/// The buffer the caller handed over is the one the vector holds afterwards —
/// which is what says the exchange moved the value rather than copying it. A
/// copy of a value like this would leave two of them naming one buffer, and the
/// second free of it is what this test would not survive.
#[test]
fn test_allocked_vec_push_carries_a_vec_by_its_buffer() {
    let mut vec = AllockedVec::with_capacity(1);
    let mut one = alloc::vec![1u8, 2, 3];
    let buffer = one.as_ptr();

    vec.push(&mut one).expect("Failed to push");

    assert_eq!(vec.as_slice(), &[alloc::vec![1u8, 2, 3]]);
    assert_eq!(vec.as_slice()[0].as_ptr(), buffer);

    // Assert zeroization!
    assert!(one.is_zeroized());
}

/// Filling to capacity leaves the allocation where it was.
///
/// Load-bearing rather than a matter of speed: a `Vec` that grew would copy
/// what it holds into a new block and free the old one without emptying it, and
/// what was in the old one is the whole of what this type exists to protect.
#[test]
fn test_allocked_vec_push_does_not_reallocate() {
    let mut vec = AllockedVec::<[u8; 32]>::with_capacity(8);

    let capacity = vec.capacity();
    let buffer = vec.as_slice().as_ptr();

    for at in 0..8 {
        vec.push(&mut [at as u8; 32]).expect("Failed to push");
    }

    assert_eq!(vec.capacity(), capacity);
    assert_eq!(vec.as_slice().as_ptr(), buffer);
}

// =============================================================================
// len(), capacity(), is_empty()
// =============================================================================

// Tested implicitly in other tests

// =============================================================================
// as_slice()
// =============================================================================

#[test]
fn test_allocked_vec_as_slice_and_as_mut_slice() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

    assert_eq!(vec.as_slice(), &[1, 2]);

    vec.as_mut_slice()[0] = 42;
    assert_eq!(vec.as_slice(), &[42, 2]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// as_mut_slice()
// =============================================================================

// Tested by test_allocked_vec_as_slice_and_as_mut_slice

// =============================================================================
// truncate()
// =============================================================================

#[test]
fn test_allocked_vec_truncate_zeroizes_removed_elements() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 0u8).expect("Failed to push");
    vec.push(&mut 0u8).expect("Failed to push");
    vec.push(&mut 0u8).expect("Failed to push");
    vec.push(&mut 1u8).expect("Failed to push");
    vec.push(&mut 2u8).expect("Failed to push");

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

// =============================================================================
// drain_from()
// =============================================================================

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

    // Assert zeroization!
    assert!(data.is_zeroized());

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

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

    let mut data = vec![3u8, 4, 5];
    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_drain_from_carries_arrays_whole() {
    let mut vec = AllockedVec::with_capacity(2);
    let mut data = [[9u8; 32], [8u8; 32]];

    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.as_slice(), &[[9u8; 32], [8u8; 32]]);

    // Assert zeroization!
    assert!(data.is_zeroized());
}

/// Elements that own their blocks cross by their pointers.
///
/// The two blocks afterwards are the two blocks the caller handed over, which
/// is what says they were exchanged rather than copied. Different lengths on
/// purpose: a length that stayed behind is then visible as a length rather than
/// as bytes that happen to agree.
#[test]
fn test_allocked_vec_drain_from_carries_vecs_by_their_buffers() {
    let mut vec = AllockedVec::with_capacity(2);
    let mut data = [alloc::vec![1u8, 2, 3], alloc::vec![7u8; 64]];

    let buffers = [data[0].as_ptr(), data[1].as_ptr()];

    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(
        vec.as_slice(),
        &[alloc::vec![1u8, 2, 3], alloc::vec![7u8; 64]]
    );

    assert_eq!(vec.as_slice()[0].as_ptr(), buffers[0]);
    assert_eq!(vec.as_slice()[1].as_ptr(), buffers[1]);

    // Assert zeroization!
    assert!(data.is_zeroized());
}

/// Draining to capacity leaves the allocation where it was.
///
/// Load-bearing rather than a matter of speed: a `Vec` that grew would copy
/// what it holds into a new block and free the old one without emptying it, and
/// what was in the old one is the whole of what this type exists to protect.
#[test]
fn test_allocked_vec_drain_from_does_not_reallocate() {
    let mut vec = AllockedVec::<[u8; 32]>::with_capacity(8);

    let capacity = vec.capacity();
    let buffer = vec.as_slice().as_ptr();

    let mut data = [[5u8; 32]; 8];

    vec.drain_from(&mut data).expect("Failed to drain_from");

    assert_eq!(vec.capacity(), capacity);
    assert_eq!(vec.as_slice().as_ptr(), buffer);
}

// =============================================================================
// realloc_with_capacity()
// =============================================================================

#[test]
fn test_allocked_vec_realloc_with_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

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

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

    let result = vec.push(&mut 3u8);

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

    vec.push(&mut 3u8).expect("Failed to vec.push(3)");
    vec.push(&mut 4u8).expect("Failed to vec.push(4)");
    vec.push(&mut 5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1u8, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

#[test]
fn test_allocked_vec_realloc_with_capacity_noop_when_sufficient() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

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

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");
    vec.push(&mut 3u8).expect("Failed to vec.push(3)");
    vec.push(&mut 4u8).expect("Failed to vec.push(4)");
    vec.push(&mut 5u8).expect("Failed to vec.push(5)");

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

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");
    vec.push(&mut 3u8).expect("Failed to vec.push(3)");
    vec.push(&mut 4u8).expect("Failed to vec.push(4)");
    vec.push(&mut 5u8).expect("Failed to vec.push(5)");

    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// fill_with_default()
// =============================================================================

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

    vec.push(&mut 1).expect("push failed");
    vec.push(&mut 2).expect("push failed");

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

    vec.push(&mut 1).expect("push failed");
    vec.push(&mut 2).expect("push failed");
    vec.push(&mut 3).expect("push failed");

    assert_eq!(vec.len(), 3);

    vec.fill_with_default();

    assert_eq!(vec.len(), 3);
    assert_eq!(vec.as_slice(), [1, 2, 3]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// change_behaviour() (test-utils feature)
// =============================================================================

#[test]
fn test_allocked_vec_behaviour_fail_at_push() {
    let mut vec = AllockedVec::with_capacity(10);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.change_behaviour(AllockedVecBehaviour::FailAtPush);

    let result = vec.push(&mut 1u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Behaviour is sticky - still fails
    let result = vec.push(&mut 2u8);

    assert!(result.is_err());
    assert!(matches!(result, Err(AllockedVecError::CapacityExceeded)));

    // Reset behaviour
    vec.change_behaviour(AllockedVecBehaviour::None);

    // Now push should work
    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
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

// =============================================================================
// as_mut_ptr() (unsafe feature)
// =============================================================================

#[test]
fn test_allocked_vec_as_mut_ptr_write_single_byte() {
    let mut vec = AllockedVec::<u8>::with_capacity(1);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 0u8).expect("Failed to push initial byte");

    let ptr = vec.as_mut_ptr();

    unsafe {
        *ptr = 0x42;
    }

    assert_eq!(vec.as_slice(), &[0x42]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// as_capacity_slice() (unsafe feature)
// =============================================================================

#[test]
fn test_allocked_vec_as_capacity_slice_returns_full_capacity() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to push");
    vec.push(&mut 2u8).expect("Failed to push");

    // len is 2, but capacity is 5
    assert_eq!(vec.len(), 2);
    assert_eq!(vec.capacity(), 5);

    // as_capacity_slice returns full capacity (zeroed by with_capacity)
    let slice = unsafe { vec.as_capacity_slice() };
    assert_eq!(slice.len(), 5);
    assert_eq!(&slice[..2], &[1, 2]);
    // Spare capacity is zeroed
    assert_eq!(&slice[2..], &[0, 0, 0]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// as_capacity_mut_slice() (unsafe feature)
// =============================================================================

#[test]
fn test_allocked_vec_as_capacity_mut_slice_allows_writing_beyond_len() {
    let mut vec = AllockedVec::<u8>::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to push");
    vec.push(&mut 2u8).expect("Failed to push");

    // Write beyond len (but within capacity)
    let slice = unsafe { vec.as_capacity_mut_slice() };
    slice[2] = 3;
    slice[3] = 4;
    slice[4] = 5;

    // len unchanged, but data is written
    assert_eq!(vec.len(), 2);

    // Verify via as_capacity_slice
    let slice = unsafe { vec.as_capacity_slice() };
    assert_eq!(slice, &[1, 2, 3, 4, 5]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// set_len() (unsafe feature)
// =============================================================================

#[test]
fn test_allocked_vec_set_len_can_shrink() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to push(1)");
    vec.push(&mut 2u8).expect("Failed to push(2)");
    vec.push(&mut 3u8).expect("Failed to push(3)");

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

    vec.push(&mut 1u8).expect("Failed to push(1)");
    vec.push(&mut 2u8).expect("Failed to push(2)");

    // Write to spare capacity first
    unsafe { vec.as_capacity_mut_slice()[2] = 3 };
    unsafe { vec.as_capacity_mut_slice()[3] = 4 };

    // SAFETY: 4 <= capacity, elements at 0..4 are initialized
    unsafe { vec.set_len(4) };

    assert_eq!(vec.len(), 4);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4]);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// Default
// =============================================================================

#[test]
fn test_allocked_vec_default() {
    let vec: AllockedVec<u8> = AllockedVec::default();

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);

    assert!(vec.is_empty());
    // Vec is zeroized since `has_been_sealed` is false.
    assert!(vec.is_zeroized());
}

// =============================================================================
// Deref
// =============================================================================

#[test]
fn test_allocked_vec_deref_to_slice() {
    let mut vec = AllockedVec::with_capacity(3);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

    // Deref allows slice methods
    assert_eq!(vec[0], 1);
    assert_eq!(vec[1], 2);
    assert_eq!(vec.len(), 2);

    // Vec is not zeroized since `has_been_sealed` is true and contains data.
    assert!(!vec.is_zeroized());
}

// =============================================================================
// PartialEq / Eq
// =============================================================================

#[test]
fn test_allocked_vec_partial_eq_equal_vecs() {
    let mut vec1 = AllockedVec::with_capacity(5);
    vec1.push(&mut 1u8).expect("Failed to push");
    vec1.push(&mut 2u8).expect("Failed to push");
    vec1.push(&mut 3u8).expect("Failed to push");

    let mut vec2 = AllockedVec::with_capacity(5);
    vec2.push(&mut 1u8).expect("Failed to push");
    vec2.push(&mut 2u8).expect("Failed to push");
    vec2.push(&mut 3u8).expect("Failed to push");

    assert_eq!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 == vec2);
}

#[test]
fn test_allocked_vec_partial_eq_different_data() {
    let mut vec1 = AllockedVec::with_capacity(5);
    vec1.push(&mut 1u8).expect("Failed to push");
    vec1.push(&mut 2u8).expect("Failed to push");

    let mut vec2 = AllockedVec::with_capacity(5);
    vec2.push(&mut 1u8).expect("Failed to push");
    vec2.push(&mut 3u8).expect("Failed to push");

    assert_ne!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 != vec2);
}

#[test]
fn test_allocked_vec_partial_eq_different_lengths() {
    let mut vec1 = AllockedVec::with_capacity(5);
    vec1.push(&mut 1u8).expect("Failed to push");
    vec1.push(&mut 2u8).expect("Failed to push");

    let mut vec2 = AllockedVec::with_capacity(5);
    vec2.push(&mut 1u8).expect("Failed to push");
    vec2.push(&mut 2u8).expect("Failed to push");
    vec2.push(&mut 3u8).expect("Failed to push");

    assert_ne!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 != vec2);
}

#[test]
fn test_allocked_vec_partial_eq_different_capacities() {
    let mut vec1 = AllockedVec::with_capacity(3);
    vec1.push(&mut 1u8).expect("Failed to push");
    vec1.push(&mut 2u8).expect("Failed to push");

    let mut vec2 = AllockedVec::with_capacity(5);
    vec2.push(&mut 1u8).expect("Failed to push");
    vec2.push(&mut 2u8).expect("Failed to push");

    // Same data, different capacity
    assert_eq!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 == vec2);
}

#[test]
fn test_allocked_vec_partial_eq_empty_vecs() {
    let vec1 = AllockedVec::<u8>::with_capacity(5);
    let vec2 = AllockedVec::<u8>::with_capacity(5);

    assert_eq!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 == vec2);
}

// =============================================================================
// Debug
// =============================================================================

#[test]
fn test_allocked_vec_debug_redacted() {
    let mut vec = AllockedVec::with_capacity(5);
    vec.push(&mut 41u8).expect("Failed to push");
    vec.push(&mut 42u8).expect("Failed to push");
    vec.push(&mut 43u8).expect("Failed to push");

    let debug_output = format!("{:?}", vec);

    assert!(debug_output.contains("AllockedVec"));
    assert!(debug_output.contains("REDACTED"));
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("capacity"));
    assert!(!debug_output.contains("41"));
    assert!(!debug_output.contains("42"));
    assert!(!debug_output.contains("43"));
}

#[test]
fn test_allocked_vec_debug_snapshot() {
    let mut vec = AllockedVec::with_capacity(5);

    // Vec is not zeroized since `has_been_sealed` is true.
    assert!(!vec.is_zeroized());

    vec.push(&mut 1u8).expect("Failed to vec.push(1)");
    vec.push(&mut 2u8).expect("Failed to vec.push(2)");

    let debug_output = format!("{:?}", vec);

    assert_eq!(
        debug_output,
        "AllockedVec { data: \"REDACTED\", len: 2, capacity: 5 }"
    );
}
