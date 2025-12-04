// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Codec benchmarks - enabled with the `benchmark` feature.

use crate::codec_buffer::CodecBuffer;

use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref,
    to_decode_zeroize_dyn_mut, to_encode_zeroize_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, DecodeZeroize, Encode, EncodeZeroize};

#[derive(Debug, Clone, PartialEq, Eq)]
struct MixedData {
    bytes_1k: Vec<u8>,
    bytes_2k: Vec<u8>,
    bytes_4k: Vec<u8>,
    bytes_8k: Vec<u8>,
    bytes_16k: Vec<u8>,
    bytes_32k: Vec<u8>,
    bytes_64k: Vec<u8>,
    bytes_128k: Vec<u8>,
    bytes_256k: Vec<u8>,
    bytes_512k: Vec<u8>,
    bytes_1m: Vec<u8>,
}

impl MixedData {
    fn new() -> Self {
        Self {
            bytes_1k: vec![1; 1024],
            bytes_2k: vec![2; 2 * 1024],
            bytes_4k: vec![4; 4 * 1024],
            bytes_8k: vec![8; 8 * 1024],
            bytes_16k: vec![16; 16 * 1024],
            bytes_32k: vec![32; 32 * 1024],
            bytes_64k: vec![64; 64 * 1024],
            bytes_128k: vec![128; 128 * 1024],
            bytes_256k: vec![255; 256 * 1024],
            bytes_512k: vec![0; 512 * 1024],
            bytes_1m: vec![1; 1024 * 1024],
        }
    }

    fn total_bytes() -> usize {
        1024 + 2 * 1024
            + 4 * 1024
            + 8 * 1024
            + 16 * 1024
            + 32 * 1024
            + 64 * 1024
            + 128 * 1024
            + 256 * 1024
            + 512 * 1024
            + 1024 * 1024
    }

    fn empty() -> Self {
        Self {
            bytes_1k: Vec::new(),
            bytes_2k: Vec::new(),
            bytes_4k: Vec::new(),
            bytes_8k: Vec::new(),
            bytes_16k: Vec::new(),
            bytes_32k: Vec::new(),
            bytes_64k: Vec::new(),
            bytes_128k: Vec::new(),
            bytes_256k: Vec::new(),
            bytes_512k: Vec::new(),
            bytes_1m: Vec::new(),
        }
    }
}

impl BytesRequired for MixedData {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let collection: [&dyn BytesRequired; 11] = [
            to_bytes_required_dyn_ref(&self.bytes_1k),
            to_bytes_required_dyn_ref(&self.bytes_2k),
            to_bytes_required_dyn_ref(&self.bytes_4k),
            to_bytes_required_dyn_ref(&self.bytes_8k),
            to_bytes_required_dyn_ref(&self.bytes_16k),
            to_bytes_required_dyn_ref(&self.bytes_32k),
            to_bytes_required_dyn_ref(&self.bytes_64k),
            to_bytes_required_dyn_ref(&self.bytes_128k),
            to_bytes_required_dyn_ref(&self.bytes_256k),
            to_bytes_required_dyn_ref(&self.bytes_512k),
            to_bytes_required_dyn_ref(&self.bytes_1m),
        ];
        bytes_required_sum(collection.into_iter())
    }
}

impl Encode for MixedData {
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let collection: [&mut dyn EncodeZeroize; 11] = [
            to_encode_zeroize_dyn_mut(&mut self.bytes_1k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_2k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_4k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_8k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_16k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_32k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_64k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_128k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_256k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_512k),
            to_encode_zeroize_dyn_mut(&mut self.bytes_1m),
        ];
        encode_fields(collection.into_iter(), buf)
    }
}

impl Decode for MixedData {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let collection: [&mut dyn DecodeZeroize; 11] = [
            to_decode_zeroize_dyn_mut(&mut self.bytes_1k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_2k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_4k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_8k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_16k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_32k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_64k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_128k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_256k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_512k),
            to_decode_zeroize_dyn_mut(&mut self.bytes_1m),
        ];
        decode_fields(collection.into_iter(), buf)
    }
}

#[test]
fn benchmark_codec_roundtrip() {
    use std::time::Instant;

    let iterations = 10000usize;
    let total_bytes_per_iter = MixedData::total_bytes();

    // Setup: encode initial data
    let mut data = MixedData::new();
    let buf_size = data.mem_bytes_required().unwrap();
    let mut global_buf = CodecBuffer::new(buf_size);
    data.encode_into(&mut global_buf).unwrap();

    let start = Instant::now();

    for i in 0..iterations {
        let mut data = MixedData::empty();
        // Decode: fills data from buf
        data.decode_from(&mut global_buf.as_mut_slice()).unwrap();
        // Encode: writes data back to buf
        let cap = data.mem_bytes_required().unwrap();
        let mut buf = CodecBuffer::new(cap);
        data.encode_into(&mut buf).unwrap();
        global_buf = buf;

        if i == 0 {
            assert_eq!(data.bytes_1k.len(), 1024, "bytes_1k len mismatch");
            assert_eq!(data.bytes_1m.len(), 1024 * 1024, "bytes_1m len mismatch");
        }
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);
    let total_bytes = total_bytes_per_iter * iterations;
    let throughput_gbps = (total_bytes as f64) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!(
        "Codec roundtrip - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}
