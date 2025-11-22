// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::aead::Buffer;

use memzer::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

use crate::aead_buffer::AeadBuffer;

#[test]
fn test_aead_buffer_memguard_traits() {
    let mut buf = AeadBuffer::default();
    buf.zeroized_reserve_exact(10)
        .expect("Failed to zeroized_reserve_exact()");
    buf.drain_slice(&mut [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("Failed to drain_slice(..)");

    // Assert (not) zeroization!
    assert!(!buf.is_zeroized());

    buf.self_zeroize();

    // Assert zeroization!
    assert!(buf.is_zeroized());

    buf.assert_zeroize_on_drop();
}

#[test]
fn test_default() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut aead_buffer = AeadBuffer::default();
    let result = catch_unwind(AssertUnwindSafe(|| {
        aead_buffer.as_mut()[0] = 1;
    }));

    assert!(result.is_err());
}

#[test]
fn test_is_empty_and_len_and_capacity() {
    let mut aead_buffer = AeadBuffer::default();
    aead_buffer
        .zeroized_reserve_exact(10)
        .expect("Failed to zeroized_reserve_exact()");

    assert!(aead_buffer.is_empty());
    assert!(aead_buffer.len() == 0);
    assert!(aead_buffer.capacity() == 10);

    aead_buffer
        .extend_from_slice(&[1])
        .expect("Failed to extend_from_slice(..)");

    assert!(!aead_buffer.is_empty());
    assert!(aead_buffer.len() == 1);
    assert!(aead_buffer.capacity() == 10);
}

#[test]
fn test_as_mut_ref() {
    fn mut_buffer(buffer: &mut dyn Buffer) {
        let slice: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        buffer
            .extend_from_slice(slice)
            .expect("Failed to extend_from_slice(..)");
    }

    let mut aead_buffer = AeadBuffer::default();
    aead_buffer
        .zeroized_reserve_exact(10)
        .expect("Failed to zeroized_reserve_exact()");

    mut_buffer(&mut aead_buffer);

    assert_eq!(
        aead_buffer.as_mut().iter().as_slice(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    )
}

#[test]
fn test_truncate_when_len_equals_capacity() {
    let mut aead_buffer = AeadBuffer::default();

    let slice: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    aead_buffer
        .zeroized_reserve_exact(slice.len())
        .expect("Failed to zeroized_reserve_exact()");
    aead_buffer
        .extend_from_slice(slice)
        .expect("Failed to extend_from_slice(..)");

    assert!(aead_buffer.len() == slice.len());
    assert!(aead_buffer.capacity() == slice.len());

    aead_buffer.truncate(2);

    assert!(aead_buffer.len() == 2);
    assert!(aead_buffer.capacity() == slice.len());

    assert_eq!(aead_buffer.as_ref(), &[0, 1]);
}

#[test]
fn test_truncate_when_len_not_equals_capacity() {
    let fixed_capacity = 20;
    let mut aead_buffer = AeadBuffer::default();

    let slice: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    aead_buffer
        .zeroized_reserve_exact(fixed_capacity)
        .expect("Failed to zeroized_reserve_exact()");
    aead_buffer
        .extend_from_slice(slice)
        .expect("Failed to extend_from_slice(..)");

    assert!(aead_buffer.len() == slice.len());
    assert!(aead_buffer.capacity() == fixed_capacity);

    aead_buffer.truncate(2);

    assert!(aead_buffer.len() == 2);
    assert!(aead_buffer.capacity() == fixed_capacity);

    assert_eq!(aead_buffer.as_ref(), &[0, 1]);

    unsafe {
        let full_slice = core::slice::from_raw_parts(aead_buffer.as_mut().as_ptr(), fixed_capacity);
        assert_eq!(full_slice.len(), fixed_capacity);
        assert_eq!(
            full_slice,
            &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}

#[test]
fn test_extend_from_slice() {
    {
        let mut empty_aead_buffer = AeadBuffer::default();

        let slice: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let result_1 = empty_aead_buffer.extend_from_slice(&[]);
        let result_2 = empty_aead_buffer.extend_from_slice(slice);

        assert!(result_1.is_ok());
        assert!(result_2.is_err());
    }

    {
        let mut aead_buffer = AeadBuffer::default();
        aead_buffer
            .zeroized_reserve_exact(5)
            .expect("Failed to zeroized_reserve_exact()");

        let slice: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let result_1 = aead_buffer.extend_from_slice(&[]);
        let result_2 = aead_buffer.extend_from_slice(slice);

        assert!(result_1.is_ok());
        assert!(result_2.is_err());
    }
}

#[test]
fn test_drain_slice_ok() {
    let fixed_capacity = 20;
    let mut array_1 = [0, 1, 2, 3, 4];
    let mut array_2 = [5, 6, 7, 8, 9];

    let mut aead_buffer = AeadBuffer::default();

    aead_buffer
        .zeroized_reserve_exact(fixed_capacity)
        .expect("Failed to zeroized_reserve_exact()");

    {
        aead_buffer
            .drain_slice(&mut array_1)
            .expect("Failed to drain_slice(..)");
        assert!(aead_buffer.len() == array_1.len());
        assert!(aead_buffer.capacity() == fixed_capacity);
    }

    assert_eq!(aead_buffer.as_ref(), &[0, 1, 2, 3, 4]);
    // Assert zeroization!
    assert!(array_1.iter().all(|b| *b == 0));

    {
        aead_buffer
            .drain_slice(&mut array_2)
            .expect("Failed to drain_slice(..)");
        assert!(aead_buffer.len() == array_1.len() + array_2.len());
        assert!(aead_buffer.capacity() == fixed_capacity);
    }

    assert_eq!(aead_buffer.as_ref(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    // Assert zeroization!
    assert!(array_2.iter().all(|b| *b == 0));
}

#[test]
fn test_drain_slice_failure() {
    let short_fixed_capacity = 2;
    let mut array = [0, 1, 2, 3, 4];

    let mut aead_buffer = AeadBuffer::default();
    aead_buffer
        .zeroized_reserve_exact(short_fixed_capacity)
        .expect("Failed to zeroized_reserve_exact()");

    let result = aead_buffer.drain_slice(&mut array);
    assert!(result.is_err());

    // Assert zeroization!
    assert!(array.iter().all(|b| *b == 0));
}

#[test]
fn test_debug() {
    let mut aead_buffer = AeadBuffer::default();

    aead_buffer
        .zeroized_reserve_exact(10)
        .expect("Failed to zeroized_reserve_exact()");
    aead_buffer
        .extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("Failed to extend_from_slice(..)");

    let str = format!("{:?}", aead_buffer);

    assert!(str.contains("AeadBuffer") && str.contains("protected"));
    assert!(!str.contains("AB"), "Debug must not leak raw bytes");
}

#[test]
#[cfg(any(test, feature = "test_utils"))]
fn test_tamper() {
    let mut aead_buffer = AeadBuffer::default();

    aead_buffer
        .zeroized_reserve_exact(10)
        .expect("Failed to zeroized_reserve_exact()");
    aead_buffer
        .extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("Failed to extend_from_slice(..)");

    aead_buffer.tamper(|v| {
        v[0] = 10;
    });

    assert_eq!(aead_buffer.as_ref(), &[10, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn test_drain_slice_checked_add_overflow() {
    use std::alloc::{Layout, alloc, dealloc};

    // To trigger overflow in checked_add, we need cur_len + other.len() > usize::MAX
    // We'll allocate a huge capacity Vec and set len = usize::MAX - 5
    // IMPORTANT: len must be <= capacity to satisfy Vec::from_raw_parts preconditions
    let fake_len = usize::MAX - 5;
    let fake_capacity = usize::MAX - 3; // capacity >= len

    let mut aead_buffer = AeadBuffer::default();

    // SAFETY: This test intentionally violates Vec invariants to test overflow handling.
    // We create a Vec with len = usize::MAX - 5 using from_raw_parts, which is technically
    // UB if we ever access the fake elements. However, we only use this Vec to trigger
    // checked_add overflow in drain_slice, which returns early before any invalid access.
    // The minimal 1-byte allocation satisfies the non-null ptr requirement.
    unsafe {
        // Allocate 1 byte (we won't actually use it, just need valid ptr)
        let layout = Layout::from_size_align(1, 1).unwrap();
        let ptr = alloc(layout);

        aead_buffer.tamper(|inner_vec| {
            // Forget old vec
            let _ = core::mem::take(inner_vec);

            // Create fake Vec with len = usize::MAX - 5
            *inner_vec = Vec::from_raw_parts(ptr, fake_len, fake_capacity);
        });
    }

    // Try to drain 10 bytes, which would overflow: (usize::MAX - 5) + 10 > usize::MAX
    let mut source = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Assert (not) zeroization!
    assert_eq!(source, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let result = aead_buffer.drain_slice(&mut source);

    // Should fail with CapacityExceededError due to checked_add overflow
    assert!(result.is_err());

    // Assert zeroization! (on error)
    assert!(source.iter().all(|&b| b == 0));

    // Cleanup: Manually drop to avoid issues
    unsafe {
        let layout = Layout::from_size_align(1, 1).unwrap();
        aead_buffer.tamper(|inner_vec| {
            let ptr = inner_vec.as_mut_ptr();

            // Forget to prevent double-free
            core::mem::forget(core::mem::take(inner_vec));

            // Free the allocated byte
            dealloc(ptr, layout);
        });
    }
}
