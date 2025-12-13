// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod is_vec_fully_zeroized_tests {
    use redoubt_util::{fast_zeroize_vec, is_vec_fully_zeroized};

    #[test]
    fn test_is_vec_fully_zeroized_empty() {
        let vec: Vec<u8> = Vec::new();
        assert!(is_vec_fully_zeroized(&vec));
    }

    #[test]
    fn test_is_vec_fully_zeroized_all_zeros() {
        let vec = vec![0u8; 10];
        assert!(is_vec_fully_zeroized(&vec));
    }

    #[test]
    fn test_is_vec_fully_zeroized_with_data() {
        let vec = vec![1u8, 2, 3];
        assert!(!is_vec_fully_zeroized(&vec));
    }

    #[test]
    fn test_is_vec_fully_zeroized_after_zeroize() {
        let mut vec = vec![1u8, 2, 3, 4, 5];
        assert!(!is_vec_fully_zeroized(&vec));

        fast_zeroize_vec(&mut vec);
        assert!(is_vec_fully_zeroized(&vec));
    }

    #[test]
    fn test_is_vec_fully_zeroized_spare_capacity() {
        let mut vec = vec![1u8, 2, 3, 4, 5];
        vec.truncate(2); // len = 2, capacity = 5

        // Manually zero the active elements
        for byte in vec.iter_mut() {
            *byte = 0;
        }

        // Spare capacity still contains old data
        assert!(!is_vec_fully_zeroized(&vec));

        // fast_zeroize_vec clears BOTH active elements AND spare capacity
        fast_zeroize_vec(&mut vec);
        assert!(is_vec_fully_zeroized(&vec));
    }

    #[test]
    fn test_is_vec_fully_zeroized_after_reserve() {
        let mut vec = vec![1u8, 2, 3];
        vec.reserve(10);

        // Reserve doesn't clear the existing data
        assert!(!is_vec_fully_zeroized(&vec));

        fast_zeroize_vec(&mut vec);
        assert!(is_vec_fully_zeroized(&vec));
    }
}
