// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests {
    use memcodec_core::{BytesRequired, CodecBuffer, Decode, Encode};
    use memcodec_derive::Codec;
    use memzer::ZeroizationProbe;

    #[test]
    fn test_derive_named_struct_roundtrip() {
        #[derive(Codec, Default, PartialEq, Debug, Clone)]
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
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = CodecBuffer::new(bytes_required);

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
        #[derive(Codec, Default, PartialEq, Debug, Clone)]
        struct TupleData(u64, Vec<u8>, u32);

        let original = TupleData(0xdeadbeef, vec![10, 20, 30], 42);
        let mut original_clone = original.clone();

        let bytes_required = original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = CodecBuffer::new(bytes_required);

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
        #[derive(Codec, Default, PartialEq, Debug, Clone)]
        struct EmptyStruct;

        let original = EmptyStruct;
        let mut original_clone = original.clone();

        let bytes_required = original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        assert_eq!(bytes_required, 0);

        let mut buf = CodecBuffer::new(1);

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
}
