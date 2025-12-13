// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod constant_time_eq_tests {
    use redoubt_util::constant_time_eq;

    #[test]
    fn test_equal_slices() {
        assert!(constant_time_eq(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_different_slices() {
        assert!(!constant_time_eq(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 6]));
    }

    #[test]
    fn test_different_lengths() {
        assert!(!constant_time_eq(&[1, 2, 3, 4, 5], &[1, 2, 3, 4]));
    }

    #[test]
    fn test_empty_slices() {
        let a: [u8; 0] = [];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn test_single_byte_difference() {
        assert!(!constant_time_eq(&[0, 0, 0, 0, 0], &[0, 0, 1, 0, 0]));
    }
}
