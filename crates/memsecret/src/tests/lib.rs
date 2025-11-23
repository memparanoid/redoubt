// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::Secret;
use memzer::{AssertZeroizeOnDrop, ZeroizationProbe};

#[test]
fn test_secret_assert_zeroization_probe_trait() {
    let mut data = vec![1u8, 2, 3, 4];
    let secret = Secret::from(&mut data);

    assert!(!secret.is_zeroized());
}

#[test]
fn test_secret_assert_zeroed_on_drop_trait() {
    let mut data = vec![1u8, 2, 3, 4];
    let secret = Secret::from(&mut data);

    secret.assert_zeroize_on_drop();
}

#[test]
fn test_secret_expose_methods() {
    let mut data = vec![1u8, 2, 3, 4];
    let mut secret = Secret::from(&mut data);

    // Test expose
    assert_eq!(secret.expose(), &vec![1u8, 2, 3, 4]);

    // Test expose_mut
    secret.expose_mut().push(5);
    assert_eq!(secret.expose(), &vec![1u8, 2, 3, 4, 5]);

    secret.expose_mut()[0] = 42;
    assert_eq!(secret.expose()[0], 42);
}

#[test]
fn test_secret_debug() {
    let mut data = vec![1u8, 2, 3, 4];
    let secret = Secret::from(&mut data);

    let debug_output = format!("{:?}", secret);
    assert_eq!(debug_output, "[REDACTED Secret]");
}

#[test]
fn test_secret_from_zeroizes_source() {
    // Test with Vec
    let mut vec_data = vec![1u8, 2, 3, 4, 5];
    let secret_vec = Secret::from(&mut vec_data);

    // Source must be zeroized
    assert!(vec_data.iter().all(|&b| b == 0));
    // Secret must contain the data
    assert_eq!(secret_vec.expose(), &vec![1u8, 2, 3, 4, 5]);

    // Test with array
    let mut array_data = [0xFFu8; 32];
    let secret_array = Secret::from(&mut array_data);

    // Source must be zeroized
    assert!(array_data.iter().all(|&b| b == 0));
    // Secret must contain the data
    assert!(secret_array.expose().iter().all(|&b| b == 0xFF));
}
