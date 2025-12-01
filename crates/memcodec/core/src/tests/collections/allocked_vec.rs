// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memalloc::AllockedVec;
use membuffer::Buffer;

use crate::collections::helpers::header_size;
use crate::traits::{BytesRequired, CodecBuffer, Decode, Encode};

/// Tests that AllockedVec decode correctly resets to the encoded size,
/// regardless of the initial capacity or content of the destination vector.
///
/// This test verifies that PreAlloc properly shrinks/expands the vector:
/// - If destination has MORE capacity than encoded size -> shrinks to encoded size
/// - If destination has LESS capacity than encoded size -> expands to encoded size
/// - If destination has existing data -> gets replaced with decoded data
///
/// The inner loop tests various initial capacities (0 to 2*i) to ensure
/// the decoded vector always matches the original, regardless of starting state.
#[test]
fn test_allocked_vec_encode_decode_with_varying_capacities() {
    let max_elements = u8::MAX as usize;

    for i in 0..max_elements {
        // Create original vector with `i` elements
        let mut original_vec = AllockedVec::with_capacity(i);
        let mut original_vec_clone = AllockedVec::with_capacity(i);

        let data = vec![u8::MAX; i];
        original_vec
            .drain_from(data.clone().as_mut_slice())
            .expect("Failed to drain_from(..)");
        original_vec_clone
            .drain_from(data.clone().as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Encode
        let bytes_required = original_vec_clone
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = Buffer::new(bytes_required);

        original_vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        assert_eq!(buf.as_slice().len(), header_size() + i);

        // Test decode with various initial capacities (smaller, equal, and larger than encoded size)
        for j in 0..i * 2 {
            let mut recovered_vec = AllockedVec::<u8>::with_capacity(j);

            let mut buf_clone = Buffer::new(buf.as_slice().len());
            buf_clone
                .write_slice(buf.as_slice().to_vec().as_mut_slice())
                .expect("Failed to write_slice(..)");

            // Pre-fill recovered_vec with garbage data to verify decode overwrites it completely
            {
                let mut data = vec![u8::MAX; j];
                recovered_vec
                    .drain_from(data.as_mut_slice())
                    .expect("Failed to drain_from(..)");
            }

            recovered_vec
                .decode_from(&mut buf_clone.as_mut_slice())
                .expect("Failed to decode_from(..)");

            // After decode, recovered_vec must exactly match original_vec
            // regardless of its initial capacity `j`
            assert_eq!(original_vec.capacity(), recovered_vec.capacity());
            assert_eq!(original_vec.len(), recovered_vec.len());
            assert_eq!(original_vec.as_slice(), recovered_vec.as_slice());
        }
    }
}
