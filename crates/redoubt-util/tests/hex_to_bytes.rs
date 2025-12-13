// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod hex_to_bytes_tests {
    use redoubt_util::hex_to_bytes;

    #[test]
    fn test_basic_hex() {
        assert_eq!(hex_to_bytes("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_lowercase() {
        assert_eq!(hex_to_bytes("abcdef"), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_uppercase() {
        assert_eq!(hex_to_bytes("ABCDEF"), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(hex_to_bytes(""), Vec::<u8>::new());
    }

    #[test]
    fn test_16_bytes() {
        let result = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    #[should_panic]
    fn test_invalid_hex_char() {
        hex_to_bytes("gg");
    }

    #[test]
    #[should_panic]
    fn test_odd_length() {
        hex_to_bytes("abc");
    }
}
