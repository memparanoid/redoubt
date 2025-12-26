// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_aead::Aead;

fn benchmark_aead_encrypt(c: &mut Criterion) {
    let mut aead = Aead::new();
    let backend_name = aead.backend_name();

    let mut group = c.benchmark_group(format!(
        "{}_encrypt",
        backend_name.to_lowercase().replace("-", "")
    ));

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = vec![0u8; aead.key_size()];
            let nonce = vec![0u8; aead.nonce_size()];
            let mut data = vec![0u8; size];
            let mut tag = vec![0u8; aead.tag_size()];

            b.iter(|| {
                aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&mut tag),
                )
                .expect("encrypt failed");
            });
        });
    }
    group.finish();
}

fn benchmark_aead_decrypt(c: &mut Criterion) {
    let mut aead = Aead::new();
    let backend_name = aead.backend_name();

    let mut group = c.benchmark_group(format!(
        "{}_decrypt",
        backend_name.to_lowercase().replace("-", "")
    ));

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = vec![0u8; aead.key_size()];
            let nonce = vec![0u8; aead.nonce_size()];
            let mut ciphertext = vec![0u8; size];
            let mut tag = vec![0u8; aead.tag_size()];

            // Encrypt once to get valid ciphertext and tag
            aead.encrypt(&key, &nonce, &[], &mut ciphertext, &mut tag)
                .expect("initial encrypt failed");

            b.iter(|| {
                // Clone ciphertext for each iteration
                let mut data = ciphertext.clone();
                aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&tag),
                )
                .expect("decrypt failed");
            });
        });
    }
    group.finish();
}

fn benchmark_aead_roundtrip(c: &mut Criterion) {
    let mut aead = Aead::new();
    let backend_name = aead.backend_name();

    let mut group = c.benchmark_group(format!(
        "{}_roundtrip",
        backend_name.to_lowercase().replace("-", "")
    ));

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("{} bytes", size), size, |b, &size| {
            let key = vec![0u8; aead.key_size()];
            let nonce = vec![0u8; aead.nonce_size()];
            let mut data = vec![0u8; size];
            let mut tag = vec![0u8; aead.tag_size()];

            b.iter(|| {
                // Re-encrypt before each decrypt to restore ciphertext
                aead.encrypt(&key, &nonce, &[], &mut data, &mut tag)
                    .expect("encrypt failed");

                aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&tag),
                )
                .expect("decrypt failed");
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_aead_encrypt,
    benchmark_aead_decrypt,
    benchmark_aead_roundtrip
);
criterion_main!(benches);
