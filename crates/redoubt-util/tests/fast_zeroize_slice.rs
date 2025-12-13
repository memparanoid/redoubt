// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod fast_zeroize_slice_tests {
    use redoubt_util::{fast_zeroize_slice, is_vec_fully_zeroized};

    #[test]
    fn test_fast_zeroize_slice_zeros_all_bytes() {
        let mut data = vec![0xABu8; 1024];
        fast_zeroize_slice(&mut data);
        assert!(is_vec_fully_zeroized(&data));
    }

    #[test]
    fn test_fast_zeroize_slice_empty_slice() {
        let mut data: Vec<u8> = vec![];
        fast_zeroize_slice(&mut data); // should not panic
        assert!(data.is_empty());
    }

    #[test]
    fn test_fast_zeroize_slice_single_byte() {
        let mut data = vec![0xFFu8];
        fast_zeroize_slice(&mut data);
        assert_eq!(data, vec![0]);
    }
}
