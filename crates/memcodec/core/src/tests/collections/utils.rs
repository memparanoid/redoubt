// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::ZeroizationProbe;

use crate::codec_buffer::CodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

/// Tests collection encode/decode with varying sizes and capacities.
///
/// For each size i in 0..set.len():
/// - Creates original collection with elements set[0..i]
/// - Encodes it
/// - For each capacity j in 0..i*2:
///   - Creates recovered with capacity j, pre-filled with garbage
///   - Decodes and verifies it matches original
pub(crate) fn test_collection_varying_capacities<T, C, F, G, H>(
    set: &[T],
    create_with_capacity: F,
    fill_from_slice: G,
    compare: H,
) where
    T: Clone,
    C: Encode + Decode + BytesRequired + Clone + ZeroizationProbe,
    F: Fn(usize) -> C,
    G: Fn(&mut C, &[T]),
    H: Fn(&C, &C) -> bool,
{
    for i in 0..set.len() {
        // Create original with elements set[0..i]
        let mut original = create_with_capacity(i);
        fill_from_slice(&mut original, &set[0..i]);

        let mut original_clone = original.clone();

        // Encode
        let bytes_required = original_clone
            .encode_bytes_required()
            .expect("Failed to get encode_bytes_required()");
        let mut buf = CodecBuffer::with_capacity(bytes_required);

        original_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Test decode with various initial capacities
        for j in 0..i * 2 {
            let mut recovered = create_with_capacity(j);
            // Pre-fill with garbage (use full set as garbage source)
            let garbage_len = j.min(set.len());
            fill_from_slice(&mut recovered, &set[0..garbage_len]);

            let mut buf_clone = CodecBuffer::with_capacity(buf.as_slice().len());
            buf_clone
                .write_slice(buf.as_slice().to_vec().as_mut_slice())
                .expect("Failed to write_slice(..)");

            let mut decode_buf = buf_clone.export_as_vec();
            recovered
                .decode_from(&mut decode_buf.as_mut_slice())
                .expect("Failed to decode_from(..)");

            assert!(
                compare(&original, &recovered),
                "decoded collection must match original"
            );

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(buf_clone.is_zeroized());
                assert!(decode_buf.is_zeroized());
                assert!(original_clone.is_zeroized());
            }
        }
    }
}
