// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA512 benchmark
//!
//! Typical usage: derive 256-bit keys from a 64-byte master key and 16-byte salt.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use memhkdf::hkdf;

const MASTER_KEY: [u8; 64] = [0x42; 64];
const SALT: [u8; 16] = [0x24; 16];
const INFO: &[u8] = b"benchmark-key-derivation";

fn bench_hkdf_derive_128_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf/derive_128bits");

    group.throughput(Throughput::Elements(1));

    group.bench_function("hkdf_sha512", |b| {
        b.iter(|| {
            let mut out = [0u8; 16];

            hkdf(
                black_box(&MASTER_KEY),
                black_box(&SALT),
                black_box(INFO),
                &mut out,
            )
            .unwrap();
            black_box(out)
        });
    });

    group.finish();
}

fn bench_hkdf_derive_256_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf/derive_256bits");

    group.throughput(Throughput::Elements(1));

    group.bench_function("hkdf_sha512", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];

            hkdf(
                black_box(&MASTER_KEY),
                black_box(&SALT),
                black_box(INFO),
                &mut out,
            )
            .unwrap();
            black_box(out)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hkdf_derive_128_bits,
    bench_hkdf_derive_256_bits
);
criterion_main!(benches);
