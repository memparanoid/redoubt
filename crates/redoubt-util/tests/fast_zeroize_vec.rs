// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod fast_zeroize_vec_tests {
    use redoubt_util::{fast_zeroize_vec, is_vec_fully_zeroized};

    #[test]
    fn test_fast_zeroize_vec_zeros_all_bytes() {
        let mut data = vec![0xABu8; 1024];
        fast_zeroize_vec(&mut data);
        assert!(is_vec_fully_zeroized(&data));
    }

    #[test]
    fn test_fast_zeroize_vec_empty_vec() {
        let mut data: Vec<u8> = vec![];
        fast_zeroize_vec(&mut data); // should not panic
        assert!(data.is_empty());
    }

    #[test]
    fn test_fast_zeroize_vec_includes_spare_capacity() {
        let mut data = vec![0xFFu8; 100];
        data.truncate(10); // len = 10, capacity = 100, spare has 0xFF

        // Before zeroize: spare capacity still has data
        assert!(!is_vec_fully_zeroized(&data));

        fast_zeroize_vec(&mut data);

        // After zeroize: entire allocation is zeroed
        assert!(is_vec_fully_zeroized(&data));
    }

    #[test]
    fn test_fast_zeroize_vec_with_capacity_only() {
        let mut data: Vec<u8> = Vec::with_capacity(100);
        // len = 0, capacity = 100

        fast_zeroize_vec(&mut data); // should not panic
        assert!(is_vec_fully_zeroized(&data));
    }
}
