// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use memcode::{MemBytesRequired, MemCodec, MemDecode, MemEncode, MemEncodeBuf};

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

// === Structs for benchmarking ===

#[derive(Clone, Serialize, Deserialize, Zeroize, MemCodec)]
#[zeroize(drop)]
struct DataU8 {
    values: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, MemCodec)]
#[zeroize(drop)]
struct DataU16 {
    values: Vec<u16>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, MemCodec)]
#[zeroize(drop)]
struct DataU32 {
    values: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, MemCodec)]
#[zeroize(drop)]
struct DataU64 {
    values: Vec<u64>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, MemCodec)]
#[zeroize(drop)]
struct MixedData {
    bytes: Vec<u8>,
    shorts: Vec<u16>,
    ints: Vec<u32>,
    longs: Vec<u64>,
}

// === Overhead isolation benchmarks ===

fn bench_bytes_required_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_required_only");
    configure_group(&mut group);

    let count = 1024;

    // u64 - worst case
    let data_u64 = DataU64 {
        values: vec![0xDEADBEEFCAFEBABE; count],
    };

    group.bench_with_input(
        BenchmarkId::new("memcode/u64", count),
        &data_u64,
        |b, d| {
            b.iter(|| black_box(d.mem_bytes_required().unwrap()));
        },
    );

    // u8
    let data_u8 = DataU8 {
        values: vec![0xAB; count],
    };

    group.bench_with_input(
        BenchmarkId::new("memcode/u8", count),
        &data_u8,
        |b, d| {
            b.iter(|| black_box(d.mem_bytes_required().unwrap()));
        },
    );

    group.finish();
}

// === Encode benchmarks ===

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    configure_group(&mut group);

    let count = 1024;

    // --- u8 ---
    let data_u8 = DataU8 {
        values: vec![0xAB; count],
    };
    group.throughput(Throughput::Bytes(count as u64));

    group.bench_with_input(BenchmarkId::new("bincode/u8", count), &data_u8, |b, d| {
        b.iter(|| black_box(bincode::serialize(d).unwrap()));
    });

    group.bench_with_input(BenchmarkId::new("memcode/u8", count), &data_u8, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = data.mem_bytes_required().unwrap();
                let mut buf = MemEncodeBuf::new(size);
                data.drain_into(&mut buf).unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });

    // --- u16 ---
    let data_u16 = DataU16 {
        values: vec![0xABCD; count],
    };
    group.throughput(Throughput::Bytes((count * 2) as u64));

    group.bench_with_input(BenchmarkId::new("bincode/u16", count), &data_u16, |b, d| {
        b.iter(|| black_box(bincode::serialize(d).unwrap()));
    });

    group.bench_with_input(BenchmarkId::new("memcode/u16", count), &data_u16, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = data.mem_bytes_required().unwrap();
                let mut buf = MemEncodeBuf::new(size);
                data.drain_into(&mut buf).unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });

    // --- u32 ---
    let data_u32 = DataU32 {
        values: vec![0xDEADBEEF; count],
    };
    group.throughput(Throughput::Bytes((count * 4) as u64));

    group.bench_with_input(BenchmarkId::new("bincode/u32", count), &data_u32, |b, d| {
        b.iter(|| black_box(bincode::serialize(d).unwrap()));
    });

    group.bench_with_input(BenchmarkId::new("memcode/u32", count), &data_u32, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = data.mem_bytes_required().unwrap();
                let mut buf = MemEncodeBuf::new(size);
                data.drain_into(&mut buf).unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });

    // --- u64 ---
    let data_u64 = DataU64 {
        values: vec![0xDEADBEEFCAFEBABE; count],
    };
    group.throughput(Throughput::Bytes((count * 8) as u64));

    group.bench_with_input(BenchmarkId::new("bincode/u64", count), &data_u64, |b, d| {
        b.iter(|| black_box(bincode::serialize(d).unwrap()));
    });

    group.bench_with_input(BenchmarkId::new("memcode/u64", count), &data_u64, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = data.mem_bytes_required().unwrap();
                let mut buf = MemEncodeBuf::new(size);
                data.drain_into(&mut buf).unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    configure_group(&mut group);

    let count = 1024;

    // --- u8 ---
    let data_u8 = DataU8 {
        values: vec![0xAB; count],
    };
    let bincode_u8 = bincode::serialize(&data_u8).unwrap();
    let mut mc_u8 = data_u8.clone();
    let size_u8 = mc_u8.mem_bytes_required().unwrap();
    let mut buf_u8 = MemEncodeBuf::new(size_u8);
    mc_u8.drain_into(&mut buf_u8).unwrap();

    group.throughput(Throughput::Bytes(count as u64));

    group.bench_with_input(
        BenchmarkId::new("bincode/u8", count),
        &bincode_u8,
        |b, enc| {
            b.iter(|| black_box(bincode::deserialize::<DataU8>(enc).unwrap()));
        },
    );

    group.bench_with_input(BenchmarkId::new("memcode/u8", count), &buf_u8, |b, buf| {
        b.iter_batched(
            || buf.as_slice().to_vec(),
            |mut bytes| {
                let mut decoded = DataU8 { values: Vec::new() };
                decoded.drain_from(&mut bytes).unwrap();
                black_box(decoded)
            },
            BatchSize::SmallInput,
        );
    });

    // --- u16 ---
    let data_u16 = DataU16 {
        values: vec![0xABCD; count],
    };
    let bincode_u16 = bincode::serialize(&data_u16).unwrap();
    let mut mc_u16 = data_u16.clone();
    let size_u16 = mc_u16.mem_bytes_required().unwrap();
    let mut buf_u16 = MemEncodeBuf::new(size_u16);
    mc_u16.drain_into(&mut buf_u16).unwrap();

    group.throughput(Throughput::Bytes((count * 2) as u64));

    group.bench_with_input(
        BenchmarkId::new("bincode/u16", count),
        &bincode_u16,
        |b, enc| {
            b.iter(|| black_box(bincode::deserialize::<DataU16>(enc).unwrap()));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("memcode/u16", count),
        &buf_u16,
        |b, buf| {
            b.iter_batched(
                || buf.as_slice().to_vec(),
                |mut bytes| {
                    let mut decoded = DataU16 { values: Vec::new() };
                    decoded.drain_from(&mut bytes).unwrap();
                    black_box(decoded)
                },
                BatchSize::SmallInput,
            );
        },
    );

    // --- u32 ---
    let data_u32 = DataU32 {
        values: vec![0xDEADBEEF; count],
    };
    let bincode_u32 = bincode::serialize(&data_u32).unwrap();
    let mut mc_u32 = data_u32.clone();
    let size_u32 = mc_u32.mem_bytes_required().unwrap();
    let mut buf_u32 = MemEncodeBuf::new(size_u32);
    mc_u32.drain_into(&mut buf_u32).unwrap();

    group.throughput(Throughput::Bytes((count * 4) as u64));

    group.bench_with_input(
        BenchmarkId::new("bincode/u32", count),
        &bincode_u32,
        |b, enc| {
            b.iter(|| black_box(bincode::deserialize::<DataU32>(enc).unwrap()));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("memcode/u32", count),
        &buf_u32,
        |b, buf| {
            b.iter_batched(
                || buf.as_slice().to_vec(),
                |mut bytes| {
                    let mut decoded = DataU32 { values: Vec::new() };
                    decoded.drain_from(&mut bytes).unwrap();
                    black_box(decoded)
                },
                BatchSize::SmallInput,
            );
        },
    );

    // --- u64 ---
    let data_u64 = DataU64 {
        values: vec![0xDEADBEEFCAFEBABE; count],
    };
    let bincode_u64 = bincode::serialize(&data_u64).unwrap();
    let mut mc_u64 = data_u64.clone();
    let size_u64 = mc_u64.mem_bytes_required().unwrap();
    let mut buf_u64 = MemEncodeBuf::new(size_u64);
    mc_u64.drain_into(&mut buf_u64).unwrap();

    group.throughput(Throughput::Bytes((count * 8) as u64));

    group.bench_with_input(
        BenchmarkId::new("bincode/u64", count),
        &bincode_u64,
        |b, enc| {
            b.iter(|| black_box(bincode::deserialize::<DataU64>(enc).unwrap()));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("memcode/u64", count),
        &buf_u64,
        |b, buf| {
            b.iter_batched(
                || buf.as_slice().to_vec(),
                |mut bytes| {
                    let mut decoded = DataU64 { values: Vec::new() };
                    decoded.drain_from(&mut bytes).unwrap();
                    black_box(decoded)
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

fn bench_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed");
    configure_group(&mut group);

    let count = 256; // 256 de cada tipo = 256 + 512 + 1024 + 2048 = 3840 bytes
    let total_bytes = count + count * 2 + count * 4 + count * 8;

    let data = MixedData {
        bytes: vec![0xAB; count],
        shorts: vec![0xABCD; count],
        ints: vec![0xDEADBEEF; count],
        longs: vec![0xDEADBEEFCAFEBABE; count],
    };

    group.throughput(Throughput::Bytes(total_bytes as u64));

    // === ENCODE ===
    // Both clone the struct for fair comparison (memcode drains/zeroizes the source)
    group.bench_with_input(BenchmarkId::new("encode/bincode", count), &data, |b, d| {
        b.iter_batched(
            || d.clone(),
            |data| black_box(bincode::serialize(&data).unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.bench_with_input(BenchmarkId::new("encode/memcode", count), &data, |b, d| {
        b.iter_batched(
            || d.clone(),
            |mut data| {
                let size = data.mem_bytes_required().unwrap();
                let mut buf = MemEncodeBuf::new(size);
                data.drain_into(&mut buf).unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });

    // === DECODE ===
    let bincode_encoded = bincode::serialize(&data).unwrap();
    let mut mc_data = data.clone();
    let size = mc_data.mem_bytes_required().unwrap();
    let mut buf = MemEncodeBuf::new(size);
    mc_data.drain_into(&mut buf).unwrap();

    group.bench_with_input(
        BenchmarkId::new("decode/bincode", count),
        &bincode_encoded,
        |b, enc| {
            b.iter(|| black_box(bincode::deserialize::<MixedData>(enc).unwrap()));
        },
    );

    group.bench_with_input(BenchmarkId::new("decode/memcode", count), &buf, |b, buf| {
        b.iter_batched(
            || buf.as_slice().to_vec(),
            |mut bytes| {
                let mut decoded = MixedData {
                    bytes: Vec::new(),
                    shorts: Vec::new(),
                    ints: Vec::new(),
                    longs: Vec::new(),
                };
                decoded.drain_from(&mut bytes).unwrap();
                black_box(decoded)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_bytes_required_only, bench_encode, bench_decode, bench_mixed);
criterion_main!(benches);
