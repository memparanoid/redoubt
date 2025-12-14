// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::RedoubtCodecBuffer;

#[cfg(feature = "zeroize")]
use redoubt_zero::{AssertZeroizeOnDrop, ZeroizationProbe};

#[cfg(feature = "zeroize")]
#[test]
fn test_codec_buffer_assert_zeroization_on_drop() {
    use redoubt_zero::FastZeroizable;

    let mut buf = RedoubtCodecBuffer::default();

    // Buffer should NOT be zeroized: it's initialized with pointers.
    assert!(!buf.is_zeroized());

    buf.fast_zeroize();

    assert!(buf.is_zeroized());

    buf.assert_zeroize_on_drop();
}

#[test]
fn test_codec_buffer_default() {
    let buf = RedoubtCodecBuffer::default();
    assert_eq!(buf.as_slice().len(), 0);
}

#[test]
fn test_codec_buffer_with_capacity_zero() {
    let buf = RedoubtCodecBuffer::with_capacity(0);
    assert_eq!(buf.as_slice().len(), 0);
}

#[test]
fn test_codec_buffer_with_capacity_64() {
    let buf = RedoubtCodecBuffer::with_capacity(64);
    assert_eq!(buf.as_slice().len(), 64);
}

#[test]
fn test_codec_buffer_realloc_with_capacity() {
    let mut buf = RedoubtCodecBuffer::default();

    // Buffer should NOT be zeroized: it's initialized with pointers.
    #[cfg(feature = "zeroize")]
    assert!(!buf.is_zeroized());

    buf.realloc_with_capacity(10);

    assert_eq!(buf.as_slice().len(), 10);
    assert_eq!(buf.as_mut_slice().len(), 10);
    // But slice should be zeroes (T::Default())
    assert!(buf.as_slice().is_zeroized());

    // Buffer should NOT be zeroized: it still have reference to AllockedVec pointers.
    #[cfg(feature = "zeroize")]
    assert!(!buf.is_zeroized());
}

#[test]
fn test_codec_buffer_clear() {
    let capacity = 10;
    let mut buf = RedoubtCodecBuffer::with_capacity(capacity);

    // Write data
    let slice = buf.as_mut_slice();
    slice.fill(0xFF);

    // Verify data is written
    assert!(buf.as_slice().iter().all(|&b| b == 0xFF));

    // Clear zeroizes content but keeps buffer usable (pointers valid)
    buf.clear();

    // Content should be zeroized
    #[cfg(feature = "zeroize")]
    {
        assert!(buf.as_slice().is_zeroized());
    }

    // Buffer is still usable - can write again
    buf.as_mut_slice()[0] = 0x42;
    assert_eq!(buf.as_slice()[0], 0x42);
}

// #[test]
// fn test_codec_buffer_as_slice() {
//     let capacity = 10;
//     let mut buf = RedoubtCodecBuffer::with_capacity(capacity);

//     // Write some data
//     let slice = buf.as_mut_slice();
//     for i in 0..capacity {
//         slice[i] = (i + 1) as u8;
//     }

//     // Verify as_slice returns correct data
//     let slice = buf.as_slice();
//     assert_eq!(slice.len(), capacity);
//     for i in 0..capacity {
//         assert_eq!(slice[i], (i + 1) as u8);
//     }
// }

#[test]
fn test_codec_buffer_as_mut_slice() {
    let capacity = 5;
    let mut buf = RedoubtCodecBuffer::with_capacity(capacity);

    // Write via as_mut_slice
    let slice = buf.as_mut_slice();
    assert_eq!(slice.len(), capacity);
    slice[0] = 0xAA;
    slice[1] = 0xBB;
    slice[2] = 0xCC;
    slice[3] = 0xDD;
    slice[4] = 0xEE;

    // Verify via as_slice
    assert_eq!(buf.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

    // Modify again
    buf.as_mut_slice()[0] = 0xFF;
    assert_eq!(buf.as_slice()[0], 0xFF);
}

#[test]
fn test_codec_buffer_len() {
    let capacity = 10;
    let buf = RedoubtCodecBuffer::with_capacity(capacity);

    // len() should return the capacity
    assert_eq!(buf.len(), capacity);

    // Verify with different capacities
    let buf_zero = RedoubtCodecBuffer::with_capacity(0);
    assert_eq!(buf_zero.len(), 0);

    let buf_large = RedoubtCodecBuffer::with_capacity(1024);
    assert_eq!(buf_large.len(), 1024);
}

#[test]
fn test_codec_buffer_is_empty() {
    let buf_empty = RedoubtCodecBuffer::with_capacity(0);
    assert!(buf_empty.is_empty());

    let buf_non_empty = RedoubtCodecBuffer::with_capacity(10);
    assert!(!buf_non_empty.is_empty());
}

#[test]
fn test_codec_buffer_to_vec() {
    let capacity = 6;
    let mut buf = RedoubtCodecBuffer::with_capacity(capacity);

    // Write via as_mut_slice
    let slice = buf.as_mut_slice();
    slice[0] = 0xAA;
    slice[1] = 0xBB;
    slice[2] = 0xCC;
    slice[3] = 0xDD;
    slice[4] = 0xEE;

    let vec = buf.export_as_vec();

    assert_eq!(vec, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00]);
    assert!(buf.is_zeroized());
}

/// Test pointer invariants after realloc_with_capacity
/// This test catches potential UB from dangling pointers after reallocation
#[test]
fn test_codec_buffer_realloc_pointer_invariants() {
    let mut buf = RedoubtCodecBuffer::with_capacity(5);

    // Write initial data to verify pointers are valid
    buf.as_mut_slice()
        .copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    assert_eq!(buf.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

    // Realloc to larger capacity - this changes internal pointers
    buf.realloc_with_capacity(10);

    // Verify pointer invariants:
    // 1. as_slice() returns valid slice with new capacity
    assert_eq!(
        buf.as_slice().len(),
        10,
        "as_slice() length should match new capacity"
    );

    // 2. as_mut_slice() returns valid mutable slice
    assert_eq!(
        buf.as_mut_slice().len(),
        10,
        "as_mut_slice() length should match new capacity"
    );

    // 3. Content is zeroed after realloc (fill_with_default)
    assert!(
        buf.as_slice().is_zeroized(),
        "realloc should zero-initialize new buffer"
    );

    // 4. Can write to buffer after realloc (pointers are valid)
    buf.as_mut_slice()
        .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(
        buf.as_slice(),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        "can write after realloc"
    );

    // Realloc to smaller capacity - another pointer update
    buf.realloc_with_capacity(3);

    // Verify invariants again:
    // Original data must be preserved
    assert_eq!(buf.as_slice().len(), 3, "as_slice() length after shrinking");
    assert_eq!(
        buf.as_mut_slice().len(),
        3,
        "as_mut_slice() length after shrinking"
    );
    assert_eq!(buf.as_slice(), &[1, 2, 3]);

    // Can still write after shrinking
    buf.as_mut_slice().copy_from_slice(&[0xFF, 0xFE, 0xFD]);
    assert_eq!(
        buf.as_slice(),
        &[0xFF, 0xFE, 0xFD],
        "can write after shrinking realloc"
    );

    // Multiple reallocs in sequence
    for new_cap in [1, 20, 5, 100, 0, 7] {
        buf.realloc_with_capacity(new_cap);
        assert_eq!(
            buf.as_slice().len(),
            new_cap,
            "length matches after realloc to {}",
            new_cap
        );
        assert_eq!(
            buf.as_mut_slice().len(),
            new_cap,
            "mut_slice length matches after realloc to {}",
            new_cap
        );

        // Verify can read/write at every capacity
        if new_cap > 0 {
            buf.as_mut_slice()[0] = 0x42;
            assert_eq!(
                buf.as_slice()[0],
                0x42,
                "can read/write at capacity {}",
                new_cap
            );
        }
    }
}
