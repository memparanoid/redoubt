// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::{is_spare_capacity_zeroized, zeroize_spare_capacity};
use memzer::ZeroizationProbe;

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
    assert!(read_spare_capacity(&vec).is_zeroized());
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
    assert!(read_spare_capacity(&vec).is_zeroized());
}

// === === === === === === === === === ===
// Tests for is_spare_capacity_zeroized
// === === === === === === === === === ===

#[test]
fn test_is_spare_capacity_zeroized_empty_spare() {
    let vec = vec![1u8, 2, 3];
    // len == capacity, no spare
    assert!(is_spare_capacity_zeroized(&vec));
}

#[test]
fn test_is_spare_capacity_zeroized_empty_vec() {
    let vec: Vec<u8> = Vec::new();
    assert!(is_spare_capacity_zeroized(&vec));
}

#[test]
fn test_is_spare_capacity_zeroized_with_data_in_spare() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    vec.truncate(2);

    // Spare capacity has old data (3, 4, 5)
    assert!(!is_spare_capacity_zeroized(&vec));
}

#[test]
fn test_is_spare_capacity_zeroized_after_zeroize() {
    let mut vec = vec![1u8, 2, 3, 4, 5];
    vec.truncate(2);

    assert!(!is_spare_capacity_zeroized(&vec));

    zeroize_spare_capacity(&mut vec);
    assert!(is_spare_capacity_zeroized(&vec));
}

#[test]
fn test_is_spare_capacity_zeroized_u32() {
    let mut vec = vec![100u32, 200, 300, 400];
    vec.truncate(2);

    // Spare capacity has old data
    assert!(!is_spare_capacity_zeroized(&vec));

    zeroize_spare_capacity(&mut vec);
    assert!(is_spare_capacity_zeroized(&vec));
}

#[test]
fn test_is_spare_capacity_zeroized_with_reserve() {
    let mut vec: Vec<u32> = Vec::with_capacity(100);
    vec.extend_from_slice(&[1, 2, 3]);

    // Fill spare with pattern
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len());
        core::ptr::write_bytes(spare_ptr as *mut u8, 0xFF, 97 * 4);
    }

    assert!(!is_spare_capacity_zeroized(&vec));

    zeroize_spare_capacity(&mut vec);
    assert!(is_spare_capacity_zeroized(&vec));
}
