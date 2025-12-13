// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};

// Fast mode: FAST_BENCH=1 cargo bench -p membench --bench codec
fn is_fast_mode() -> bool {
    std::env::var("FAST_BENCH")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn configure_group(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    if is_fast_mode() {
        group.measurement_time(std::time::Duration::from_millis(500));
        group.sample_size(10);
    } else {
        group.measurement_time(std::time::Duration::from_secs(3));
        group.sample_size(50);
    }
}

// === Single struct for all benchmarks ===

#[derive(Clone, Default, Codec)]
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
        Self::default()
    }
}

// === ENCODE ===

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcodec_encode");
    configure_group(&mut group);

    let data = MixedData::new();
    let total_bytes = MixedData::total_bytes();

    group.throughput(Throughput::Bytes(total_bytes as u64));

    group.bench_with_input(BenchmarkId::new("encode", total_bytes), &data, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = BytesRequired::mem_bytes_required(&data)
                    .expect("failed to calculate bytes required");
                let mut buf = CodecBuffer::with_capacity(size);
                data.encode_into(&mut buf)
                    .expect("failed to encode data");
                black_box(buf)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

// === DECODE ===

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcodec_decode");
    configure_group(&mut group);

    let data = MixedData::new();
    let total_bytes = MixedData::total_bytes();

    // Prepare encoded buffer
    let mut mc_data = data.clone();
    let size = BytesRequired::mem_bytes_required(&mc_data)
        .expect("failed to calculate bytes required");
    let mut memcodec_buf = CodecBuffer::with_capacity(size);
    mc_data.encode_into(&mut memcodec_buf)
        .expect("failed to encode data");
    let memcodec_encoded: Vec<u8> = memcodec_buf.as_slice().to_vec();

    // Verify memcodec decode works correctly before benchmarking
    {
        let mut verify_bytes = memcodec_encoded.clone();
        let mut verify_decoded = MixedData::empty();
        verify_decoded
            .decode_from(&mut verify_bytes.as_mut_slice())
            .expect("failed to decode verification data");
        assert_eq!(verify_decoded.bytes_1k.len(), 1024, "bytes_1k len mismatch");
        assert_eq!(
            verify_decoded.bytes_1m.len(),
            1024 * 1024,
            "bytes_1m len mismatch"
        );
        assert!(
            verify_decoded.bytes_1k.iter().all(|&x| x == 1),
            "bytes_1k data mismatch"
        );
        assert!(
            verify_decoded.bytes_1m.iter().all(|&x| x == 1),
            "bytes_1m data mismatch"
        );
    }

    group.throughput(Throughput::Bytes(total_bytes as u64));

    group.bench_with_input(
        BenchmarkId::new("decode", total_bytes),
        &memcodec_encoded,
        |b, enc| {
            b.iter_batched(
                || enc.clone(),
                |mut bytes| {
                    let mut decoded = MixedData::empty();
                    decoded.decode_from(&mut bytes.as_mut_slice())
                        .expect("failed to decode data");
                    // Force work by checking data
                    assert_eq!(decoded.bytes_1m.len(), 1024 * 1024);
                    black_box(decoded)
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

// === ROUNDTRIP ===

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcodec_roundtrip");
    configure_group(&mut group);

    let data = MixedData::new();
    let total_bytes = MixedData::total_bytes();

    group.throughput(Throughput::Bytes(total_bytes as u64));

    group.bench_with_input(BenchmarkId::new("roundtrip", total_bytes), &data, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = BytesRequired::mem_bytes_required(&data)
                    .expect("failed to calculate bytes required");
                let mut buf = CodecBuffer::with_capacity(size);

                data.encode_into(&mut buf)
                    .expect("failed to encode data");

                let mut decoded = MixedData::empty();
                let mut bytes = buf.as_mut_slice();
                decoded.decode_from(&mut bytes)
                    .expect("failed to decode data");
                black_box(decoded)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_roundtrip);
criterion_main!(benches);
