// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_util::zeroize_spare_capacity;

fn read_spare_capacity<T>(vec: &Vec<T>) -> Vec<u8> {
    let from = vec.len() * core::mem::size_of::<T>();
    let to = vec.capacity() * core::mem::size_of::<T>();
    let base = vec.as_ptr().cast::<u8>();

    // SAFETY: the range is the spare, inside the allocation, and every test
    // here writes it before reading: a truncate leaves what it dropped, a
    // `write_bytes` its pattern, the wipe its zeros. Never written, these
    // bytes are uninitialized and reading them is undefined.
    (from..to)
        .map(|at| unsafe { base.add(at).read() })
        .collect()
}

#[test]
fn test_zeroize_spare_capacity_basic() {
    let mut vec = vec![0xFFu8; 100];
    vec.truncate(10);

    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0xFF));

    zeroize_spare_capacity(&mut vec);

    assert!(vec.iter().all(|&b| b == 0xFF));
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}

#[test]
fn test_zeroize_spare_capacity_empty_spare() {
    let mut vec = vec![0xFFu8; 10];

    zeroize_spare_capacity(&mut vec);

    assert!(vec.iter().all(|&b| b == 0xFF));
}

#[test]
fn test_zeroize_spare_capacity_empty_vec() {
    let mut vec: Vec<u8> = Vec::new();

    zeroize_spare_capacity(&mut vec);

    assert!(vec.is_empty());
}

#[test]
fn test_zeroize_spare_capacity_with_reserved() {
    let mut vec: Vec<u8> = Vec::with_capacity(100);
    vec.extend_from_slice(&[0xAA; 10]);

    // SAFETY: a hundred bytes reserved and ten held, so the ninety past `len`
    // are the spare, inside the allocation.
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len());
        core::ptr::write_bytes(spare_ptr, 0xBB, 90);
    }

    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0xBB));

    zeroize_spare_capacity(&mut vec);

    assert!(vec.iter().all(|&b| b == 0xAA));
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}

#[test]
fn test_zeroize_spare_capacity_u32() {
    let mut vec = vec![100u32, 200, 300, 400];
    vec.truncate(2);

    assert!(read_spare_capacity(&vec).iter().any(|&b| b != 0));

    zeroize_spare_capacity(&mut vec);

    assert_eq!(vec, [100, 200]);
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}

#[test]
fn test_zeroize_spare_capacity_u32_with_reserved() {
    let mut vec: Vec<u32> = Vec::with_capacity(100);
    vec.extend_from_slice(&[1, 2, 3]);

    // SAFETY: a hundred words reserved and three held, so the ninety-seven past
    // `len` are the spare, inside the allocation.
    unsafe {
        let spare_ptr = vec.as_mut_ptr().add(vec.len());
        core::ptr::write_bytes(spare_ptr.cast::<u8>(), 0xFF, 97 * 4);
    }

    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0xFF));

    zeroize_spare_capacity(&mut vec);

    assert_eq!(vec, [1, 2, 3]);
    assert!(read_spare_capacity(&vec).iter().all(|&b| b == 0));
}
