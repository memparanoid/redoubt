// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA512 vs BLAKE3 key derivation benchmark
//!
//! Typical usage: derive 256-bit keys from a 64-byte master key and 16-byte salt.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use memhkdf::hkdf;

const IKM: [u8; 64] = [0x42; 64];
const SALT: [u8; 16] = [0x24; 16];
const INFO: &[u8] = b"benchmark-key-derivation";
const BLAKE3_CONTEXT: &str = "memora benchmark key derivation";

fn bench_hkdf_derive_128_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf/derive_128bits");

    group.throughput(Throughput::Elements(1));

    group.bench_function("hkdf_sha512", |b| {
        b.iter(|| {
            let mut out = [0u8; 16];

            hkdf(black_box(&IKM), black_box(&SALT), black_box(INFO), &mut out).unwrap();
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

            hkdf(black_box(&IKM), black_box(&SALT), black_box(INFO), &mut out).unwrap();
            black_box(out)
        });
    });

    group.finish();
}

fn bench_blake3_derive_256_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3/derive_256bits");

    group.throughput(Throughput::Elements(1));

    // Option 1: derive_key with concat (salt + ikm)
    group.bench_function("derive_key_concat", |b| {
        b.iter(|| {
            let mut material = [0u8; 80];
            material[..16].copy_from_slice(&SALT);
            material[16..].copy_from_slice(&IKM);
            let key = blake3::derive_key(black_box(BLAKE3_CONTEXT), black_box(&material));
            black_box(key)
        });
    });

    // Option 2: keyed_hash (pre-derive kdf_key once, then hash salt)
    let kdf_key: [u8; 32] = blake3::derive_key(BLAKE3_CONTEXT, &IKM);
    group.bench_function("keyed_hash", |b| {
        b.iter(|| {
            let key = blake3::keyed_hash(black_box(&kdf_key), black_box(&SALT));
            black_box(key)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hkdf_derive_128_bits,
    bench_hkdf_derive_256_bits,
    bench_blake3_derive_256_bits
);
criterion_main!(benches);
