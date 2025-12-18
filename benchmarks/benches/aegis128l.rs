// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_aead::{AeadBackend, aegis_asm::Aegis128L};

fn benchmark_aegis128l_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("aegis128l_roundtrip");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = [0u8; 16];
            let nonce = [0u8; 16];
            let mut data = vec![0u8; size];
            let mut tag = [0u8; 16];
            let mut aead = Aegis128L::default();

            b.iter(|| {
                // Re-encrypt before each decrypt to restore ciphertext
                aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);

                aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&tag),
                )
                .expect("aegis128l decrypt failed");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_aegis128l_roundtrip);
criterion_main!(benches);
