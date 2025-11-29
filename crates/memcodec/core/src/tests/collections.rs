// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
use zeroize::Zeroize;

use crate::CodecBuffer;
use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref, to_decode_dyn_mut,
    to_encode_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

// Test struct with two 1MB vecs
#[derive(Debug, PartialEq, Eq)]
struct TwoVecs {
    a: Vec<u8>,
    b: Vec<u8>,
}

// Same struct as criterion benchmark
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize)]
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
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let collection: [&mut dyn Encode; 11] = [
            to_encode_dyn_mut(&mut self.bytes_1k),
            to_encode_dyn_mut(&mut self.bytes_2k),
            to_encode_dyn_mut(&mut self.bytes_4k),
            to_encode_dyn_mut(&mut self.bytes_8k),
            to_encode_dyn_mut(&mut self.bytes_16k),
            to_encode_dyn_mut(&mut self.bytes_32k),
            to_encode_dyn_mut(&mut self.bytes_64k),
            to_encode_dyn_mut(&mut self.bytes_128k),
            to_encode_dyn_mut(&mut self.bytes_256k),
            to_encode_dyn_mut(&mut self.bytes_512k),
            to_encode_dyn_mut(&mut self.bytes_1m),
        ];
        encode_fields(collection.into_iter(), buf)
    }
}

impl Decode for MixedData {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let collection: [&mut dyn Decode; 11] = [
            to_decode_dyn_mut(&mut self.bytes_1k),
            to_decode_dyn_mut(&mut self.bytes_2k),
            to_decode_dyn_mut(&mut self.bytes_4k),
            to_decode_dyn_mut(&mut self.bytes_8k),
            to_decode_dyn_mut(&mut self.bytes_16k),
            to_decode_dyn_mut(&mut self.bytes_32k),
            to_decode_dyn_mut(&mut self.bytes_64k),
            to_decode_dyn_mut(&mut self.bytes_128k),
            to_decode_dyn_mut(&mut self.bytes_256k),
            to_decode_dyn_mut(&mut self.bytes_512k),
            to_decode_dyn_mut(&mut self.bytes_1m),
        ];
        decode_fields(collection.into_iter(), buf)
    }
}

impl BytesRequired for TwoVecs {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let collection: [&dyn BytesRequired; 2] = [
            to_bytes_required_dyn_ref(&self.a),
            to_bytes_required_dyn_ref(&self.b),
        ];
        bytes_required_sum(collection.into_iter())
    }
}

impl Encode for TwoVecs {
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let collection: [&mut dyn Encode; 2] = [
            to_encode_dyn_mut(&mut self.a),
            to_encode_dyn_mut(&mut self.b),
        ];
        encode_fields(collection.into_iter(), buf)
    }
}

impl Decode for TwoVecs {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let collection: [&mut dyn Decode; 2] = [
            to_decode_dyn_mut(&mut self.a),
            to_decode_dyn_mut(&mut self.b),
        ];
        decode_fields(collection.into_iter(), buf)
    }
}

#[test]
fn test_huge_vec() {
    use std::time::Instant;

    let iterations = 1000 as usize;
    let start = Instant::now();

    for _ in 0..iterations {
        let mut vec = vec![u8::MAX; 1024];
        let bytes_required = vec
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = Buffer::new(bytes_required);

        vec.encode_into(&mut buf).expect("Failed to drain_into(..)");
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);

    println!("Total: {:?}, Per iter: {:?}", elapsed, per_iter);
}

#[test]
fn test_bulk_copy_only() {
    use std::time::Instant;

    let iterations = 100_000 as usize;
    // Pre-allocate buffer once
    let vec = vec![u8::MAX; 1024];
    let buf_size = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut buf = Buffer::new(buf_size);

    let start = Instant::now();

    for _ in 0..iterations {
        let mut vec = vec![u8::MAX; 1024];

        // Direct bulk copy test - skip mem_bytes_required
        vec.encode_into(&mut buf).expect("Failed to drain_into(..)");

        std::hint::black_box(&buf);

        buf.clear();
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);

    println!(
        "Bulk copy only - Total: {:?}, Per iter: {:?}",
        elapsed, per_iter
    );
}

#[test]
fn test_roundtrip_vec_u8() {
    // Original data
    let original: Vec<u8> = (0..=255).collect();

    // Encode
    let mut to_encode = original.clone();
    let bytes_required = to_encode
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    to_encode
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    let mut decoded: Vec<u8> = Vec::new();
    decoded
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    // Verify
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_benchmark() {
    use std::time::Instant;

    let iterations = 100_000usize;
    // let iterations = 1_000usize;

    let data_size = 1024usize; // 1KB
    // let data_size = 8192usize; // 8KB
    // let data_size = 10 * 1024 * 1024; // 10 MiB

    // Pre-allocate buffer
    let sample: Vec<u8> = vec![0xAB; data_size];
    let buf_size = sample
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(buf_size);

    let start = Instant::now();

    for _ in 0..iterations {
        // Encode
        let mut to_encode: Vec<u8> = vec![0xAB; data_size];
        to_encode
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        let mut decoded: Vec<u8> = Vec::new();
        decoded
            .decode_from(&mut buf.as_mut_slice())
            .expect("Failed to decode_from(..)");

        std::hint::black_box(&decoded);

        buf.clear();
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);

    println!(
        "Roundtrip (encode+decode) - Total: {:?}, Per iter: {:?}",
        elapsed, per_iter
    );
}

#[test]
fn test_two_vecs_roundtrip() {
    let size = 1024 * 1024; // 1MB each

    // Original data
    let original_a: Vec<u8> = vec![0xAA; size];
    let original_b: Vec<u8> = vec![0xBB; size];

    // Encode
    let mut to_encode = TwoVecs {
        a: original_a.clone(),
        b: original_b.clone(),
    };
    let bytes_required = to_encode
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    to_encode
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    let mut decoded = TwoVecs {
        a: Vec::new(),
        b: Vec::new(),
    };
    decoded
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    // Verify
    let original = TwoVecs {
        a: original_a,
        b: original_b,
    };
    assert_eq!(original, decoded);
}

#[test]
fn test_two_vecs_benchmark() {
    use std::time::Instant;

    let iterations = 1000usize;
    let size = 1024 * 1024; // 1MB each, 2MB total

    let start = Instant::now();

    for i in 0..iterations {
        let mut to_encode = TwoVecs {
            a: vec![0xAA; size],
            b: vec![0xBB; size],
        };

        // Reallocate buffer each iteration (fair comparison)
        let buf_size = to_encode.mem_bytes_required().unwrap();
        let mut buf = Buffer::new(buf_size);

        to_encode.encode_into(&mut buf).unwrap();

        let mut decoded = TwoVecs {
            a: Vec::new(),
            b: Vec::new(),
        };
        decoded.decode_from(&mut buf.as_mut_slice()).unwrap();

        // Verify first iteration
        if i == 0 {
            assert_eq!(decoded.a.len(), size, "a len mismatch");
            assert_eq!(decoded.b.len(), size, "b len mismatch");
            assert!(decoded.a.iter().all(|&x| x == 0xAA), "a data mismatch");
            assert!(decoded.b.iter().all(|&x| x == 0xBB), "b data mismatch");
        }

        std::hint::black_box(&decoded);
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);
    let total_bytes = size * 2 * iterations;
    let throughput_gbps = (total_bytes as f64) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!(
        "TwoVecs roundtrip - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}

#[test]
fn test_mixed_data_roundtrip() {
    use std::time::Instant;

    let iterations = 10000usize;
    let warmup = 1000usize;
    let total_bytes_per_iter = MixedData::total_bytes();

    // Source data to clone from (like criterion)
    let source = MixedData::new();

    // Warmup
    for _ in 0..warmup {
        let mut to_encode = source.clone();
        let buf_size = to_encode.mem_bytes_required().unwrap();
        let mut buf = Buffer::new(buf_size);
        to_encode.encode_into(&mut buf).unwrap();
        let mut decoded = MixedData::empty();
        decoded.decode_from(&mut buf.as_mut_slice()).unwrap();
        std::hint::black_box(&decoded);
    }

    let start = Instant::now();

    for i in 0..iterations {
        let mut to_encode = source.clone();
        let buf_size = to_encode.mem_bytes_required().unwrap();
        let mut buf = Buffer::new(buf_size);

        to_encode.encode_into(&mut buf).unwrap();

        let mut decoded = MixedData::empty();
        decoded.decode_from(&mut buf.as_mut_slice()).unwrap();

        // Verify first iteration
        if i == 0 {
            assert_eq!(decoded.bytes_1k.len(), 1024, "bytes_1k len mismatch");
            assert_eq!(decoded.bytes_1m.len(), 1024 * 1024, "bytes_1m len mismatch");
            assert!(
                decoded.bytes_1k.iter().all(|&x| x == 1),
                "bytes_1k data mismatch"
            );
            assert!(
                decoded.bytes_1m.iter().all(|&x| x == 1),
                "bytes_1m data mismatch"
            );
        }

        std::hint::black_box(&decoded);
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);
    let total_bytes = total_bytes_per_iter * iterations;
    let throughput_gbps = (total_bytes as f64) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!(
        "MixedData roundtrip - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}

#[test]
fn test_mixed_data_roundtrip_fast() {
    use std::time::Instant;

    let iterations = 10000usize;
    let warmup = 1000usize;
    let total_bytes_per_iter = MixedData::total_bytes();

    // Setup: encode initial data
    let mut data = MixedData::new();
    let buf_size = data.mem_bytes_required().unwrap();
    let mut global_buf = Buffer::new(buf_size);
    data.encode_into(&mut global_buf).unwrap();

    // // Warmup
    // for _ in 0..warmup {
    //     data.decode_from(&mut buf.as_mut_slice()).unwrap();
    //     data.encode_into(&mut buf).unwrap();
    // }

    let start = Instant::now();

    for i in 0..iterations {
        let mut data = MixedData::empty();
        // Decode: fills data from buf
        data.decode_from(&mut global_buf.as_mut_slice()).unwrap();
        // Encode: writes data back to buf
        let cap = data.mem_bytes_required().unwrap();
        let mut buf = Buffer::new(cap);
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
        "MixedData roundtrip_fast - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}

#[test]
fn test_mixed_data_decode_only() {
    use std::time::Instant;

    let iterations = 100usize;
    let warmup = 20usize;
    let total_bytes_per_iter = MixedData::total_bytes();

    // Prepare encoded data once
    let mut source = MixedData::new();
    let buf_size = source.mem_bytes_required().unwrap();
    let mut buf = Buffer::new(buf_size);
    source.encode_into(&mut buf).unwrap();
    let encoded: Vec<u8> = buf.as_slice().to_vec();

    // Warmup
    for _ in 0..warmup {
        let mut bytes = encoded.clone();
        let mut decoded = MixedData::empty();
        decoded.decode_from(&mut bytes.as_mut_slice()).unwrap();
        std::hint::black_box(&decoded);
    }

    // Pre-clone buffers (like criterion setup)
    let mut cloned_buffers: Vec<Vec<u8>> = (0..iterations).map(|_| encoded.clone()).collect();

    let start = Instant::now();

    for i in 0..iterations {
        let mut bytes = std::mem::take(&mut cloned_buffers[i]);
        let mut decoded = MixedData::empty();
        decoded.decode_from(&mut bytes.as_mut_slice()).unwrap();

        // Verify first iteration
        if i == 0 {
            assert_eq!(decoded.bytes_1k.len(), 1024, "bytes_1k len mismatch");
            assert_eq!(decoded.bytes_1m.len(), 1024 * 1024, "bytes_1m len mismatch");
            assert!(
                decoded.bytes_1k.iter().all(|&x| x == 1),
                "bytes_1k data mismatch"
            );
            assert!(
                decoded.bytes_1m.iter().all(|&x| x == 1),
                "bytes_1m data mismatch"
            );
        }

        std::hint::black_box(&decoded);
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);
    let total_bytes = total_bytes_per_iter * iterations;
    let throughput_gbps = (total_bytes as f64) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!(
        "MixedData decode only - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}

#[test]
fn test_alloc_overhead() {
    use std::time::Instant;

    let iterations = 10000usize;
    let warmup = 1000usize;
    let total_bytes_per_iter = MixedData::total_bytes();

    let source = MixedData::new();

    // Warmup
    for _ in 0..warmup {
        let data = source.clone();
        let buf_size = data.mem_bytes_required().unwrap();
        let buf = Buffer::new(buf_size);
        let decoded = MixedData::empty();
        std::hint::black_box((&buf, &decoded));
    }

    let start = Instant::now();

    for _ in 0..iterations {
        // Encode side: clone + bytes_required + Buffer::new
        let data = MixedData::empty();
        let buf_size = data.mem_bytes_required().unwrap();
        let buf = Buffer::new(buf_size);
        // Decode side: empty struct
        std::hint::black_box((&buf, &data));
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);
    let total_bytes = total_bytes_per_iter * iterations;
    let throughput_gbps = (total_bytes as f64) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!(
        "Alloc overhead (clone + bytes_required + Buffer::new + empty) - Total: {:?}, Per iter: {:?}, Throughput: {:.2} GB/s",
        elapsed, per_iter, throughput_gbps
    );
}
