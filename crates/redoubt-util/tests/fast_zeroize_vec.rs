// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod fast_zeroize_vec_tests {
    use redoubt_util::fast_zeroize_vec;

    fn read_allocation(vec: &Vec<u8>) -> Vec<u8> {
        let base = vec.as_ptr();

        // SAFETY: the range is the allocation, and every test here writes all
        // of it before reading: the elements and what a truncate dropped, or
        // the wipe's zeros. Never written, the spare is uninitialized and
        // reading it is undefined.
        (0..vec.capacity())
            .map(|at| unsafe { base.add(at).read() })
            .collect()
    }

    #[test]
    fn test_fast_zeroize_vec_zeros_all_bytes() {
        let mut data = vec![0xABu8; 1024];
        fast_zeroize_vec(&mut data);
        assert!(read_allocation(&data).iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fast_zeroize_vec_empty_vec() {
        let mut data: Vec<u8> = vec![];
        fast_zeroize_vec(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_fast_zeroize_vec_includes_spare_capacity() {
        let mut data = vec![0xFFu8; 100];
        data.truncate(10);

        assert!(read_allocation(&data).iter().all(|&b| b == 0xFF));

        fast_zeroize_vec(&mut data);

        assert!(read_allocation(&data).iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fast_zeroize_vec_with_capacity_only() {
        let mut data: Vec<u8> = Vec::with_capacity(100);

        fast_zeroize_vec(&mut data);
        assert!(read_allocation(&data).iter().all(|&b| b == 0));
    }
}
