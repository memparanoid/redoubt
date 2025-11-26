// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests {
    use memutil::u32_from_le;

    #[test]
    fn test_little_endian_conversion() {
        let mut value: u32 = 0;
        let mut bytes = [0x01, 0x02, 0x03, 0x04];

        u32_from_le(&mut value, &mut bytes);

        assert_eq!(value, 0x04030201);
    }

    #[test]
    fn test_source_bytes_zeroized() {
        let mut value: u32 = 0;
        let mut bytes = [0xDE, 0xAD, 0xBE, 0xEF];

        u32_from_le(&mut value, &mut bytes);

        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_zero_bytes() {
        let mut value: u32 = 0xFFFFFFFF;
        let mut bytes = [0x00, 0x00, 0x00, 0x00];

        u32_from_le(&mut value, &mut bytes);

        assert_eq!(value, 0);
        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_max_value() {
        let mut value: u32 = 0;
        let mut bytes = [0xFF, 0xFF, 0xFF, 0xFF];

        u32_from_le(&mut value, &mut bytes);

        assert_eq!(value, 0xFFFFFFFF);
        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_overwrites_destination() {
        let mut value: u32 = 0xDEADBEEF;
        let mut bytes = [0x01, 0x00, 0x00, 0x00];

        u32_from_le(&mut value, &mut bytes);

        assert_eq!(value, 1);
    }
}
