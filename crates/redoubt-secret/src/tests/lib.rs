// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::ZeroizationProbe;

use crate::RedoubtSecret;

#[test]
fn test_secret_assert_zeroization_probe_trait() {
    let mut data = vec![1u8, 2, 3, 4];
    let secret = RedoubtSecret::from(&mut data);

    assert!(!secret.is_zeroized());
}

#[test]
fn test_secret_as_ref_as_mut() {
    let mut data = vec![1u8, 2, 3, 4];
    let mut secret = RedoubtSecret::from(&mut data);

    // Test as_ref
    assert_eq!(secret.as_ref(), &vec![1u8, 2, 3, 4]);

    // Test as_mut
    secret.as_mut().push(5);
    assert_eq!(secret.as_ref(), &vec![1u8, 2, 3, 4, 5]);

    secret.as_mut()[0] = 42;
    assert_eq!(secret.as_ref()[0], 42);
}

#[test]
fn test_secret_debug() {
    let mut data = vec![1u8, 2, 3, 4];
    let secret = RedoubtSecret::from(&mut data);

    let debug_output = format!("{:?}", secret);
    assert_eq!(debug_output, "[REDACTED RedoubtSecret]");
}

#[test]
fn test_secret_from_zeroizes_source() {
    // Test with Vec
    let mut vec_data = vec![1u8, 2, 3, 4, 5];
    let secret_vec = RedoubtSecret::from(&mut vec_data);

    // Source must be zeroized
    assert!(vec_data.iter().all(|&b| b == 0));
    // Secret must contain the data
    assert_eq!(secret_vec.as_ref(), &vec![1u8, 2, 3, 4, 5]);

    // Test with array
    let mut array_data = [0xFFu8; 32];
    let secret_array = RedoubtSecret::from(&mut array_data);

    // Source must be zeroized
    assert!(array_data.iter().all(|&b| b == 0));
    // Secret must contain the data
    assert!(secret_array.as_ref().iter().all(|&b| b == 0xFF));
}

#[test]
fn test_secret_replace() {
    let mut original_data = vec![1u8, 2, 3, 4, 5];
    let mut secret = RedoubtSecret::from(&mut original_data);
    assert_eq!(secret.as_ref(), &vec![1u8, 2, 3, 4, 5]);

    let mut new_data = vec![10u8, 20, 30];
    secret.replace(&mut new_data);

    assert!(new_data.iter().all(|&b| b == 0));
    assert_eq!(secret.as_ref(), &vec![10u8, 20, 30]);
}
