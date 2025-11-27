// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

use crate::buffer::Buffer;

#[test]
fn test_buffer_zeroization() {
    let elements = 10;
    let mut buf = Buffer::new(elements);

    let slice = buf.as_mut_slice();

    for i in 0..elements {
        slice[i] = i as u8;
    }

    assert!(!buf.is_zeroized());
    buf.zeroize();
    assert!(buf.is_zeroized());

    let buf = Buffer::new(100);
    buf.assert_zeroize_on_drop();
}

#[test]
fn test_as_slice() {
    let capacity = 10;
    let mut buf = Buffer::new(capacity);

    // Write some data
    let slice = buf.as_mut_slice();
    for i in 0..capacity {
        slice[i] = (i + 1) as u8;
    }

    // Verify as_slice returns correct data
    let slice = buf.as_slice();
    assert_eq!(slice.len(), capacity);
    for i in 0..capacity {
        assert_eq!(slice[i], (i + 1) as u8);
    }
}

#[test]
fn test_as_mut_slice() {
    let capacity = 5;
    let mut buf = Buffer::new(capacity);

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
fn test_clear() {
    let capacity = 10;
    let mut buf = Buffer::new(capacity);

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
    assert!(buf.as_slice().iter().all(|&b| b == 0x00));

    // Buffer is still usable - can write again
    buf.as_mut_slice()[0] = 0x42;
    assert_eq!(buf.as_slice()[0], 0x42);
}
