// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod is_slice_zeroized_tests {
    use memutil::is_slice_zeroized;

    #[test]
    fn test_is_slice_zeroized_empty() {
        let slice: &[u8] = &[];
        assert!(is_slice_zeroized(slice));
    }

    #[test]
    fn test_is_slice_zeroized_all_zeros() {
        let data = [0u8; 10];
        assert!(is_slice_zeroized(&data));
    }

    #[test]
    fn test_is_slice_zeroized_with_data() {
        let data = [1u8, 2, 3];
        assert!(!is_slice_zeroized(&data));
    }

    #[test]
    fn test_is_slice_zeroized_single_nonzero_byte() {
        let data = [0u8, 0, 1, 0, 0];
        assert!(!is_slice_zeroized(&data));
    }

    #[test]
    fn test_is_slice_zeroized_first_byte_nonzero() {
        let data = [1u8, 0, 0, 0];
        assert!(!is_slice_zeroized(&data));
    }

    #[test]
    fn test_is_slice_zeroized_last_byte_nonzero() {
        let data = [0u8, 0, 0, 1];
        assert!(!is_slice_zeroized(&data));
    }
}
