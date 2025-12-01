// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::zeroize_spare_capacity;

/// Helper to read spare capacity bytes (unsafe but sound for testing).
fn read_spare_capacity(vec: &Vec<u8>) -> Vec<u8> {
    let mut spare = Vec::new();
    let base = vec.as_ptr();
    for i in vec.len()..vec.capacity() {
        unsafe {
            spare.push(*base.add(i));
        }
    }
    spare
}

#[test]
fn test_zeroize_spare_capacity_basic() {
    let mut vec = vec![0xFFu8; 100];
    vec.truncate(10);

    // Spare capacity should have 0xFF
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0xFF));

    zeroize_spare_capacity(&mut vec);

    // Active elements unchanged
    assert!(vec.iter().all(|&b| b == 0xFF));
    // Spare capacity zeroed
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}

#[test]
fn test_zeroize_spare_capacity_empty_spare() {
    let mut vec = vec![0xFFu8; 10];
    // len == capacity, no spare

    zeroize_spare_capacity(&mut vec);

    // Should not panic, elements unchanged
    assert!(vec.iter().all(|&b| b == 0xFF));
}

#[test]
fn test_zeroize_spare_capacity_empty_vec() {
    let mut vec: Vec<u8> = Vec::new();

    zeroize_spare_capacity(&mut vec);

    // Should not panic
    assert!(vec.is_empty());
}

#[test]
fn test_zeroize_spare_capacity_with_reserved() {
    let mut vec: Vec<u8> = Vec::with_capacity(100);
    vec.extend_from_slice(&[0xAA; 10]);

    // Fill spare with pattern (simulating previous data)
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len());
        core::ptr::write_bytes(spare_ptr, 0xBB, 90);
    }

    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0xBB));

    zeroize_spare_capacity(&mut vec);

    // Active elements unchanged
    assert!(vec.iter().all(|&b| b == 0xAA));
    // Spare capacity zeroed
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}
