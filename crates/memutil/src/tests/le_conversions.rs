// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod le_conversions_tests {
    use crate::*;
    use memzer::ZeroizationProbe;

    // u16 tests
    #[test]
    fn test_u16_from_le() {
        let mut value: u16 = 0;
        let mut bytes = [0x01, 0x02];
        u16_from_le(&mut value, &mut bytes);
        assert_eq!(value, 0x0201);
        assert_eq!(bytes, [0, 0]);
    }

    #[test]
    fn test_u16_to_le() {
        let mut value: u16 = 0x0201;
        let mut bytes = [0u8; 2];
        u16_to_le(&mut value, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02]);
        assert_eq!(value, 0);
    }

    // u32 tests
    #[test]
    fn test_u32_from_le() {
        let mut value: u32 = 0;
        let mut bytes = [0x01, 0x02, 0x03, 0x04];
        u32_from_le(&mut value, &mut bytes);
        assert_eq!(value, 0x04030201);
        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_u32_to_le() {
        let mut value: u32 = 0x04030201;
        let mut bytes = [0u8; 4];
        u32_to_le(&mut value, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(value, 0);
    }

    // u64 tests
    #[test]
    fn test_u64_from_le() {
        let mut value: u64 = 0;
        let mut bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        u64_from_le(&mut value, &mut bytes);
        assert_eq!(value, 0x0807060504030201);
        assert_eq!(bytes, [0; 8]);
    }

    #[test]
    fn test_u64_to_le() {
        let mut value: u64 = 0x0807060504030201;
        let mut bytes = [0u8; 8];
        u64_to_le(&mut value, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(value, 0);
    }

    // usize tests
    #[test]
    fn test_usize_from_le() {
        let mut value: usize = 0;
        #[cfg(target_pointer_width = "64")]
        let mut bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        #[cfg(target_pointer_width = "32")]
        let mut bytes = [0x01, 0x02, 0x03, 0x04];

        usize_from_le(&mut value, &mut bytes);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value, 0x0807060504030201);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(value, 0x04030201);

        assert!(bytes.is_zeroized());
    }

    #[test]
    fn test_usize_to_le() {
        #[cfg(target_pointer_width = "64")]
        let mut value: usize = 0x0807060504030201;
        #[cfg(target_pointer_width = "32")]
        let mut value: usize = 0x04030201;

        #[cfg(target_pointer_width = "64")]
        let mut bytes = [0u8; 8];
        #[cfg(target_pointer_width = "32")]
        let mut bytes = [0u8; 4];

        usize_to_le(&mut value, &mut bytes);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);

        assert_eq!(value, 0);
    }

    // roundtrip tests
    #[test]
    fn test_u16_roundtrip() {
        let original: u16 = 0xABCD;
        let mut value = original;
        let mut bytes = [0u8; 2];
        u16_to_le(&mut value, &mut bytes);
        let mut restored: u16 = 0;
        u16_from_le(&mut restored, &mut bytes);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_u32_roundtrip() {
        let original: u32 = 0xDEADBEEF;
        let mut value = original;
        let mut bytes = [0u8; 4];
        u32_to_le(&mut value, &mut bytes);
        let mut restored: u32 = 0;
        u32_from_le(&mut restored, &mut bytes);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_u64_roundtrip() {
        let original: u64 = 0xDEADBEEFCAFEBABE;
        let mut value = original;
        let mut bytes = [0u8; 8];
        u64_to_le(&mut value, &mut bytes);
        let mut restored: u64 = 0;
        u64_from_le(&mut restored, &mut bytes);
        assert_eq!(restored, original);
    }

    // edge cases
    #[test]
    fn test_zero_values() {
        let mut u16_val: u16 = 0;
        let mut u16_bytes = [0u8; 2];
        u16_to_le(&mut u16_val, &mut u16_bytes);
        assert_eq!(u16_bytes, [0, 0]);

        let mut u32_val: u32 = 0;
        let mut u32_bytes = [0u8; 4];
        u32_to_le(&mut u32_val, &mut u32_bytes);
        assert_eq!(u32_bytes, [0, 0, 0, 0]);

        let mut u64_val: u64 = 0;
        let mut u64_bytes = [0u8; 8];
        u64_to_le(&mut u64_val, &mut u64_bytes);
        assert_eq!(u64_bytes, [0; 8]);
    }

    #[test]
    fn test_max_values() {
        let mut u16_val: u16 = u16::MAX;
        let mut u16_bytes = [0u8; 2];
        u16_to_le(&mut u16_val, &mut u16_bytes);
        assert_eq!(u16_bytes, [0xFF, 0xFF]);
        assert_eq!(u16_val, 0);

        let mut u32_val: u32 = u32::MAX;
        let mut u32_bytes = [0u8; 4];
        u32_to_le(&mut u32_val, &mut u32_bytes);
        assert_eq!(u32_bytes, [0xFF; 4]);
        assert_eq!(u32_val, 0);

        let mut u64_val: u64 = u64::MAX;
        let mut u64_bytes = [0u8; 8];
        u64_to_le(&mut u64_val, &mut u64_bytes);
        assert_eq!(u64_bytes, [0xFF; 8]);
        assert_eq!(u64_val, 0);
    }
}
