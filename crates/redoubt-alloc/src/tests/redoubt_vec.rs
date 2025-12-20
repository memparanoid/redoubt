// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::RedoubtVec;
use redoubt_zero::ZeroizationProbe;

// =============================================================================
// new()
// =============================================================================

#[test]
fn test_new() {
    let vec: RedoubtVec<u8> = RedoubtVec::new();

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);
}

// =============================================================================
// with_capacity()
// =============================================================================

#[test]
fn test_with_capacity() {
    let vec: RedoubtVec<u8> = RedoubtVec::with_capacity(10);

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 10);
}

// =============================================================================
// from_mut_slice()
// =============================================================================

#[test]
fn test_from_mut_slice() {
    let mut data = [1u8, 2, 3, 4, 5];
    let vec = RedoubtVec::from_mut_slice(&mut data);

    assert_eq!(vec.as_slice(), [1, 2, 3, 4, 5]);
    assert!(data.is_zeroized());
}

// =============================================================================
// len(), is_empty(), capacity()
// =============================================================================

// Tested implicitly in other tests

// =============================================================================
// drain_value()
// =============================================================================

#[test]
fn test_drain_value_single() {
    let mut vec = RedoubtVec::new();
    let mut value = 42u8;

    vec.drain_value(&mut value);

    assert_eq!(vec.len(), 1);
    assert_eq!(vec[0], 42);
    assert_eq!(value, 0); // zeroized
}

#[test]
fn test_drain_value_grows_to_power_of_2() {
    let mut vec = RedoubtVec::new();

    // First drain: 0 → 1
    let mut v1 = 1u8;
    vec.drain_value(&mut v1);
    assert_eq!(vec.capacity(), 1);

    // Second drain: 1 → 2
    let mut v2 = 2u8;
    vec.drain_value(&mut v2);
    assert_eq!(vec.capacity(), 2);

    // Third drain: 2 → 4
    let mut v3 = 3u8;
    vec.drain_value(&mut v3);
    assert_eq!(vec.capacity(), 4);

    // Fourth drain: stays at 4
    let mut v4 = 4u8;
    vec.drain_value(&mut v4);
    assert_eq!(vec.capacity(), 4);

    // Fifth drain: 4 → 8
    let mut v5 = 5u8;
    vec.drain_value(&mut v5);
    assert_eq!(vec.capacity(), 8);
}

// =============================================================================
// extend_from_mut_slice()
// =============================================================================

#[test]
fn test_extend_from_mut_slice() {
    let mut vec = RedoubtVec::new();
    let mut src = [1u8, 2, 3, 4, 5];

    vec.extend_from_mut_slice(&mut src);

    // Verify data was moved
    assert_eq!(vec.len(), 5);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);

    // Verify source was zeroized
    assert!(src.is_zeroized());
}

#[test]
fn test_extend_from_mut_slice_grows() {
    let mut vec = RedoubtVec::with_capacity(2);
    let mut v1 = 1u8;
    let mut v2 = 2u8;

    vec.drain_value(&mut v1);
    vec.drain_value(&mut v2);

    let mut src = [3u8, 4, 5, 6, 7];
    vec.extend_from_mut_slice(&mut src);

    // Should grow to accommodate: len=2 + src.len=5 = 7 → next_power_of_two = 8
    assert_eq!(vec.len(), 7);
    assert_eq!(vec.capacity(), 8);
    assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5, 6, 7]);

    // Source zeroized
    assert!(src.is_zeroized());
}

#[test]
fn test_extend_from_mut_slice_zeroizes_default_values() {
    #[derive(Debug, PartialEq, Clone, Copy, Default)]
    struct TestStruct {
        value: u32,
    }

    impl redoubt_zero::ZeroizeMetadata for TestStruct {
        const CAN_BE_BULK_ZEROIZED: bool = true;
    }

    impl redoubt_zero::FastZeroizable for TestStruct {
        fn fast_zeroize(&mut self) {
            self.value = 0;
        }
    }

    impl redoubt_zero::ZeroizationProbe for TestStruct {
        fn is_zeroized(&self) -> bool {
            self.value == 0
        }
    }

    let mut vec = RedoubtVec::new();
    let mut src = [
        TestStruct { value: 1 },
        TestStruct { value: 2 },
        TestStruct { value: 3 },
    ];

    vec.extend_from_mut_slice(&mut src);

    assert_eq!(vec.len(), 3);
    assert_eq!(vec[0].value, 1);
    assert_eq!(vec[1].value, 2);
    assert_eq!(vec[2].value, 3);

    // Source should be zeroized
    assert!(src.is_zeroized());
}

#[test]
fn test_extend_from_mut_slice_with_sufficient_capacity() {
    use redoubt_zero::ZeroizationProbe;

    // Create with large capacity
    let mut vec = RedoubtVec::with_capacity(1000);
    let initial_capacity = vec.capacity();

    // Drain multiple small slices without exceeding capacity
    for _ in 0..10 {
        let mut src = [42u8, 43, 44, 45];
        vec.extend_from_mut_slice(&mut src);

        // Verify source was zeroized
        assert!(src.is_zeroized());

        // Verify capacity did NOT grow
        assert_eq!(vec.capacity(), initial_capacity);
    }

    // Final length should be 10 * 4 = 40 elements
    assert_eq!(vec.len(), 40);
    assert_eq!(vec.capacity(), initial_capacity);
}

#[test]
fn test_maybe_grow_to_single_allocation() {
    let mut vec = RedoubtVec::new();

    // Drain a large slice should do only ONE grow
    let mut src = [0u8; 100];
    for (i, item) in src.iter_mut().enumerate() {
        *item = i as u8;
    }

    vec.extend_from_mut_slice(&mut src);

    // Should grow to next_power_of_two(100) = 128
    assert_eq!(vec.len(), 100);
    assert_eq!(vec.capacity(), 128);

    // Verify data
    for i in 0..100 {
        assert_eq!(vec[i], i as u8);
    }
}

// =============================================================================
// drain_value()
// =============================================================================

#[test]
fn test_drain_value() {
    let mut vec = RedoubtVec::new();
    let mut value = 42u8;

    vec.drain_value(&mut value);

    assert_eq!(vec.len(), 1);
    assert_eq!(vec[0], 42);

    // Source zeroized
    assert_eq!(value, 0);
}

// =============================================================================
// clear()
// =============================================================================

#[test]
fn test_clear() {
    let mut vec = RedoubtVec::new();
    let mut v1 = 1u8;
    let mut v2 = 2u8;
    let mut v3 = 3u8;
    vec.drain_value(&mut v1);
    vec.drain_value(&mut v2);
    vec.drain_value(&mut v3);

    // Assert zeroization
    assert!(v1.is_zeroized());
    assert!(v2.is_zeroized());
    assert!(v3.is_zeroized());

    vec.clear();

    assert_eq!(vec.len(), 0);
    assert!(vec.is_empty());
}

// =============================================================================
// as_slice()
// =============================================================================

#[test]
fn test_as_slice() {
    let mut vec = RedoubtVec::new();
    let mut v1 = 1u8;
    let mut v2 = 2u8;
    let mut v3 = 3u8;
    vec.drain_value(&mut v1);
    vec.drain_value(&mut v2);
    vec.drain_value(&mut v3);

    // Assert zeroization
    assert!(v1.is_zeroized());
    assert!(v2.is_zeroized());
    assert!(v3.is_zeroized());

    let slice = vec.as_slice();
    assert_eq!(slice, &[1, 2, 3]);
}

// =============================================================================
// as_mut_slice()
// =============================================================================

#[test]
fn test_as_mut_slice() {
    let mut vec = RedoubtVec::new();
    let mut v1 = 1u8;
    let mut v2 = 2u8;
    let mut v3 = 3u8;

    vec.drain_value(&mut v1);
    vec.drain_value(&mut v2);
    vec.drain_value(&mut v3);

    // Assert zeroization
    assert!(v1.is_zeroized());
    assert!(v2.is_zeroized());
    assert!(v3.is_zeroized());

    let slice_mut = vec.as_mut_slice();
    slice_mut[1] = 42;

    assert_eq!(vec.as_slice(), &[1, 42, 3]);
}

// =============================================================================
// as_vec()
// =============================================================================

#[test]
fn test_as_vec() {
    let mut vec = RedoubtVec::new();
    let mut data = vec![1u8, 2, 3];

    vec.extend_from_mut_slice(&mut data);
    assert!(data.is_zeroized());

    let vec_ref = vec.as_vec();

    assert_eq!(vec_ref.len(), 3);
    assert_eq!(vec_ref[0], 1);
    assert_eq!(vec_ref[1], 2);
    assert_eq!(vec_ref[2], 3);
}

// =============================================================================
// as_mut_vec()
// =============================================================================

#[test]
fn test_as_mut_vec() {
    let mut vec = RedoubtVec::new();
    let mut data = vec![10u8, 20, 30];

    vec.extend_from_mut_slice(&mut data);
    assert!(data.is_zeroized());

    let vec_mut_ref = vec.as_mut_vec();
    vec_mut_ref.push(40);

    assert_eq!(vec.len(), 4);
    assert_eq!(vec[3], 40);
}

// =============================================================================
// Default
// =============================================================================

#[test]
fn test_default() {
    let vec: RedoubtVec<u8> = RedoubtVec::default();

    assert_eq!(vec.len(), 0);
    assert_eq!(vec.capacity(), 0);
    assert!(vec.is_empty());
}

// =============================================================================
// PartialEq / Eq
// =============================================================================

#[test]
fn test_partial_eq_equal_vecs() {
    let mut vec1 = RedoubtVec::new();
    let mut src1 = [1u8, 2, 3];
    vec1.extend_from_mut_slice(&mut src1);
    assert!(src1.is_zeroized());

    let mut vec2 = RedoubtVec::new();
    let mut src2 = [1u8, 2, 3];
    vec2.extend_from_mut_slice(&mut src2);
    assert!(src2.is_zeroized());

    assert_eq!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 == vec2);
}

#[test]
fn test_partial_eq_different_vecs() {
    let mut vec1 = RedoubtVec::new();
    let mut src1 = [1u8, 2, 3];
    vec1.extend_from_mut_slice(&mut src1);
    assert!(src1.is_zeroized());

    let mut vec2 = RedoubtVec::new();
    let mut src2 = [1u8, 2, 4];
    vec2.extend_from_mut_slice(&mut src2);
    assert!(src2.is_zeroized());

    assert_ne!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 != vec2);
}

#[test]
fn test_partial_eq_different_lengths() {
    let mut vec1 = RedoubtVec::new();
    let mut src1 = [1u8, 2];
    vec1.extend_from_mut_slice(&mut src1);
    assert!(src1.is_zeroized());

    let mut vec2 = RedoubtVec::new();
    let mut src2 = [1u8, 2, 3];
    vec2.extend_from_mut_slice(&mut src2);
    assert!(src2.is_zeroized());

    assert_ne!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 != vec2);
}

#[test]
fn test_partial_eq_empty_vecs() {
    let vec1: RedoubtVec<u8> = RedoubtVec::new();
    let vec2: RedoubtVec<u8> = RedoubtVec::new();

    assert_eq!(vec1.as_slice(), vec2.as_slice());
    assert!(vec1 == vec2);
}

// =============================================================================
// Deref / DerefMut
// =============================================================================

#[test]
fn test_deref() {
    let mut vec = RedoubtVec::new();
    let mut src = [1u8, 2, 3];

    vec.extend_from_mut_slice(&mut src);
    assert!(src.is_zeroized());

    // Deref to slice
    let slice: &[u8] = &vec;
    assert_eq!(slice, &[1, 2, 3]);

    // DerefMut to slice
    let slice_mut: &mut [u8] = &mut vec;
    slice_mut[1] = 42;

    assert_eq!(vec[1], 42);
}

// =============================================================================
// Debug
// =============================================================================

#[test]
fn test_debug_redacted() {
    let mut vec = RedoubtVec::new();
    let mut src = [42u8, 43, 44];

    vec.extend_from_mut_slice(&mut src);
    assert!(src.is_zeroized());

    let debug_output = format!("{:?}", vec);

    assert!(debug_output.contains("RedoubtVec"));
    assert!(debug_output.contains("REDACTED"));
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("capacity"));
    // Verify actual data values are not in the output
    assert!(!debug_output.contains("42"));
    assert!(!debug_output.contains("43"));
    assert!(!debug_output.contains("44"));
}

// =============================================================================
// default_init_to_size()
// =============================================================================

#[test]
#[cfg(feature = "default_init")]
fn test_default_init_to_size_with_bulk_zeroizable() {
    let mut vec = RedoubtVec::<u8>::new();

    // Initialize with bulk-zeroizable type (u8)
    vec.default_init_to_size(100);

    assert_eq!(vec.len(), 100);
    assert!(vec.capacity() >= 100);

    // Should be zero-initialized
    assert!(vec.is_zeroized());
}

#[test]
#[cfg(feature = "default_init")]
fn test_default_init_to_size_with_complex_type() {
    #[derive(Debug, PartialEq, Clone, Copy)]
    struct TestStruct {
        value: u32,
    }

    impl Default for TestStruct {
        fn default() -> Self {
            Self { value: 42 }
        }
    }

    impl redoubt_zero::ZeroizeMetadata for TestStruct {
        const CAN_BE_BULK_ZEROIZED: bool = false;
    }

    impl redoubt_zero::FastZeroizable for TestStruct {
        fn fast_zeroize(&mut self) {
            self.value = 0;
        }
    }

    impl redoubt_zero::ZeroizationProbe for TestStruct {
        fn is_zeroized(&self) -> bool {
            self.value == 0
        }
    }

    let mut vec = RedoubtVec::<TestStruct>::new();

    // Initialize with complex type
    vec.default_init_to_size(50);

    assert_eq!(vec.len(), 50);
    assert!(vec.capacity() >= 50);

    // All elements should be zeroized after default_init_to_size
    assert!(vec.is_zeroized());
}

#[test]
#[cfg(feature = "default_init")]
fn test_default_init_to_size_clears_existing_data() {
    let mut vec = RedoubtVec::<u8>::new();
    let mut src = [1u8, 2, 3];
    vec.extend_from_mut_slice(&mut src);
    assert!(src.is_zeroized());

    assert_eq!(vec.len(), 3);

    // Re-initialize to different size
    vec.default_init_to_size(10);

    assert_eq!(vec.len(), 10);
    // All zeros (bulk zeroizable type)
    assert!(vec.is_zeroized());
}

#[test]
#[cfg(feature = "default_init")]
fn test_default_init_to_size_large() {
    let mut vec = RedoubtVec::<u8>::new();

    // Test with large size to ensure performance path works
    vec.default_init_to_size(10_000);

    assert_eq!(vec.len(), 10_000);
    assert!(vec.capacity() >= 10_000);
    assert!(vec.is_zeroized());
}

#[test]
#[cfg(feature = "default_init")]
fn test_default_init_to_size_zero() {
    let mut vec = RedoubtVec::<u8>::new();
    let mut src = [1u8, 2];
    vec.extend_from_mut_slice(&mut src);
    assert!(src.is_zeroized());

    // Initialize to size 0
    vec.default_init_to_size(0);

    assert_eq!(vec.len(), 0);
    assert!(vec.is_empty());
}
