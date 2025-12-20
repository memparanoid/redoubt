// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests {
    use redoubt_codec_core::{BytesRequired, Decode, Encode, RedoubtCodecBuffer};
    use redoubt_codec_derive::RedoubtCodec;
    use redoubt_zero::ZeroizationProbe;

    #[test]
    fn test_derive_named_struct_roundtrip() {
        #[derive(RedoubtCodec, Default, PartialEq, Debug, Clone)]
        struct TestData {
            pub value: u64,
            pub data: Vec<u8>,
            pub flag: bool,
        }

        let original = TestData {
            value: 0x1234567890abcdef,
            data: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let mut original_clone = original.clone();

        let bytes_required = original
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

        // Encode
        original_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = TestData::default();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        assert_eq!(recovered, original);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }

    #[test]
    fn test_derive_tuple_struct_roundtrip() {
        #[derive(RedoubtCodec, Default, PartialEq, Debug, Clone)]
        struct TupleData(u64, Vec<u8>, u32);

        let original = TupleData(0xdeadbeef, vec![10, 20, 30], 42);
        let mut original_clone = original.clone();

        let bytes_required = original
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

        // Encode
        original_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = TupleData::default();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        assert_eq!(recovered, original);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }

    #[test]
    fn test_derive_unit_struct() {
        #[derive(RedoubtCodec, Default, PartialEq, Debug, Clone)]
        struct EmptyStruct;

        let original = EmptyStruct;
        let mut original_clone = original.clone();

        let bytes_required = original
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        assert_eq!(bytes_required, 0);

        let mut buf = RedoubtCodecBuffer::with_capacity(1);

        // Encode
        original_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = EmptyStruct;
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        assert_eq!(recovered, original);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }

    #[test]
    fn test_derive_struct_with_option_fields() {
        #[derive(RedoubtCodec, Default, PartialEq, Debug, Clone)]
        struct OptionalData {
            pub id: u64,
            pub name: Option<Vec<u8>>,
            pub count: Option<u32>,
            pub active: bool,
        }

        // Test with None values
        let original_none = OptionalData {
            id: 0x99,
            name: None,
            count: None,
            active: false,
        };
        let mut original_none_clone = original_none.clone();

        let bytes_required = original_none
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

        original_none_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        let mut decode_buf = buf.export_as_vec();
        let mut recovered = OptionalData::default();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        assert_eq!(recovered, original_none);

        #[cfg(feature = "zeroize")]
        {
            assert!(original_none_clone.name.is_zeroized());
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }

        // Test with Some values
        let original_some = OptionalData {
            id: 0x42,
            name: Some(vec![b'f', b'o', b'o']),
            count: Some(123),
            active: true,
        };
        let mut original_some_clone = original_some.clone();

        let bytes_required = original_some
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

        original_some_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        let mut decode_buf = buf.export_as_vec();
        let mut recovered = OptionalData::default();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        assert_eq!(recovered, original_some);

        #[cfg(feature = "zeroize")]
        {
            assert!(original_some_clone.name.is_zeroized());
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }
}
