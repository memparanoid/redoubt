// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_aead::{AeadBackend, xchacha20poly1305::XChacha20Poly1305};

fn benchmark_xchacha20poly1305_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_encrypt");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = [0u8; 32];
            let nonce = [0u8; 24];
            let mut data = vec![0u8; size];
            let mut tag = [0u8; 16];
            let mut aead = XChacha20Poly1305::default();

            b.iter(|| {
                aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&mut tag),
                );
            });
        });
    }
    group.finish();
}

fn benchmark_xchacha20poly1305_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_decrypt");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = [0u8; 32];
            let nonce = [0u8; 24];
            let mut data = vec![0u8; size];
            let mut tag = [0u8; 16];
            let mut aead = XChacha20Poly1305::default();

            // Encrypt first
            aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);

            b.iter(|| {
                aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&tag),
                )
                .expect("xchacha20poly1305 decrypt failed");
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_xchacha20poly1305_encrypt,
    benchmark_xchacha20poly1305_decrypt
);
criterion_main!(benches);
