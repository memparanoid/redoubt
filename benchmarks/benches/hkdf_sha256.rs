// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_hkdf::hkdf;

fn benchmark_hkdf_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf_sha256");

    // RFC 5869 limits OKM to 255 * 32 = 8160 bytes
    // Test common key sizes
    for okm_len in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Bytes(*okm_len as u64));
        group.bench_with_input(format!("{} bytes OKM", okm_len), okm_len, |b, &okm_len| {
            let salt = b"benchmark-salt";
            let ikm = b"input-key-material-for-hkdf-benchmark";
            let info = b"benchmark-context-info";
            let mut okm = vec![0u8; okm_len];

            b.iter(|| {
                hkdf(
                    black_box(salt),
                    black_box(ikm),
                    black_box(info),
                    black_box(&mut okm),
                )
                .expect("hkdf failed");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_hkdf_sha256);
criterion_main!(benches);
