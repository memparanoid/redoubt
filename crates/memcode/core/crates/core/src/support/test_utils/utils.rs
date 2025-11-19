// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub fn tamper_encoded_bytes_for_tests(bytes: &mut Vec<u8>) {
    bytes.clear();
}

#[cfg(test)]
mod tests {
    use crate::MemEncode;
    use crate::mem_encode_buf::MemEncodeBuf;
    use crate::traits::{MemBytesRequired, MemDecode};

    use super::tamper_encoded_bytes_for_tests;

    #[test]
    fn test_tamper_encoded_bytes_for_tests() {
        let mut primitive = 0u8;
        let mut empty_collection: [u8; 0] = [];

        let mut buf_for_primitive = MemEncodeBuf::new(
            empty_collection
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );
        let mut buf_for_collection = MemEncodeBuf::new(
            empty_collection
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );
        primitive
            .drain_into(&mut buf_for_primitive)
            .expect("Failed to drain_into(..)");
        empty_collection
            .drain_into(&mut buf_for_collection)
            .expect("Failed to drain_into(..)");

        let mut tampered_primitive_bytes = buf_for_primitive.as_slice().to_vec();
        let mut tampered_empty_collection_bytes = buf_for_collection.as_slice().to_vec();

        tamper_encoded_bytes_for_tests(&mut tampered_primitive_bytes);
        tamper_encoded_bytes_for_tests(&mut tampered_empty_collection_bytes);

        let result_1 = empty_collection.drain_from(&mut tampered_empty_collection_bytes);
        let result_2 = primitive.drain_from(&mut tampered_empty_collection_bytes);

        assert!(result_1.is_err());
        assert!(result_2.is_err());
    }
}
