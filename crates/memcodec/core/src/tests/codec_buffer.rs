// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{Decode, codec_buffer::CodecBuffer};

#[cfg(feature = "zeroize")]
use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

#[cfg(feature = "zeroize")]
#[test]
fn test_codec_buffer_assert_zeroization_on_drop() {
    use memzer::FastZeroizable;

    let mut buf = CodecBuffer::default();

    // Buffer should NOT be zeroized: it's initialized with pointers.
    assert!(!buf.is_zeroized());

    buf.fast_zeroize();

    assert!(buf.is_zeroized());

    buf.assert_zeroize_on_drop();
}

#[test]
fn test_codec_buffer_default() {
    let buf = CodecBuffer::default();
    assert_eq!(buf.as_slice().len(), 0);
}

#[test]
fn test_codec_buffer_new_with_zero_capacity() {
    let buf = CodecBuffer::new(0);
    assert_eq!(buf.as_slice().len(), 0);
}

#[test]
fn test_codec_buffer_new_with_64_capacity() {
    let buf = CodecBuffer::new(64);
    assert_eq!(buf.as_slice().len(), 64);
}

#[test]
fn test_codec_buffer_realloc_with_capacity() {
    let mut buf = CodecBuffer::default();

    // Buffer should NOT be zeroized: it's initialized with pointers.
    #[cfg(feature = "zeroize")]
    assert!(!buf.is_zeroized());

    buf.realloc_with_capacity(10);

    assert_eq!(buf.as_slice().len(), 10);
    assert_eq!(buf.as_mut_slice().len(), 10);
    // But slice should be zeroes (T::Default())
    assert!(buf.as_slice().iter().all(|b| *b == 0));

    // Buffer should NOT be zeroized: it still have reference to AllockedVec pointers.
    #[cfg(feature = "zeroize")]
    assert!(!buf.is_zeroized());
}

#[test]
fn test_codec_buffer_clear() {
    let capacity = 10;
    let mut buf = CodecBuffer::new(capacity);

    // Write data
    let slice = buf.as_mut_slice();
    for i in 0..capacity {
        slice[i] = 0xFF;
    }

    // Verify data is written
    assert!(buf.as_slice().iter().all(|&b| b == 0xFF));

    // Clear zeroizes content but keeps buffer usable (pointers valid)
    buf.clear();

    // Content should be zeroized
    #[cfg(feature = "zeroize")]
    {
        assert!(buf.as_slice().iter().all(|&b| b == 0x00));
    }

    // Buffer is still usable - can write again
    buf.as_mut_slice()[0] = 0x42;
    assert_eq!(buf.as_slice()[0], 0x42);
}

// #[test]
// fn test_codec_buffer_as_slice() {
//     let capacity = 10;
//     let mut buf = CodecBuffer::new(capacity);

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
    let mut buf = CodecBuffer::new(capacity);

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
    let buf = CodecBuffer::new(capacity);

    // len() should return the capacity
    assert_eq!(buf.len(), capacity);

    // Verify with different capacities
    let buf_zero = CodecBuffer::new(0);
    assert_eq!(buf_zero.len(), 0);

    let buf_large = CodecBuffer::new(1024);
    assert_eq!(buf_large.len(), 1024);
}

#[test]
fn test_bytes_written() {
    let total_elements = 100;
    let capacity = total_elements * size_of::<usize>();
    let mut buf = CodecBuffer::new(capacity);

    assert_eq!(buf.bytes_written(), 0);

    for mut i in 0..total_elements {
        assert_eq!(buf.bytes_written(), i * size_of::<usize>());
        buf.write(&mut i).expect("Failed to write(..)");
    }

    assert_eq!(buf.bytes_written(), capacity);
}

#[test]
fn test_split_by_sizes() {
    let mut sizes = vec![];

    let primitive_size = size_of::<usize>();
    let fields_qt = 10;
    let capacity = (fields_qt * primitive_size) * ((fields_qt * primitive_size) + 1) / 2;
    let mut buf = CodecBuffer::new(capacity);

    let mut size = 0;
    for i in 0..fields_qt {
        for mut j in 0..i {
            size += primitive_size;
            buf.write(&mut j).expect("Failed to write(..)");
        }
        sizes.push(size);
    }

    let result = buf.split_by_sizes(&sizes);
    insta::assert_debug_snapshot!(result);
}
