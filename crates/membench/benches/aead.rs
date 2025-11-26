// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD benchmarks: memaead vs RustCrypto chacha20poly1305
//!
//! Compares the "traditional" allocating API that most users use.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

// RustCrypto
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};

// Ours
use memaead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 24] = [0x24; 24];
const AAD: &[u8] = b"";

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let plaintext = vec![0xAB; size];

        group.throughput(Throughput::Bytes(size as u64));

        // RustCrypto (traditional API)
        group.bench_with_input(BenchmarkId::new("rustcrypto", size), &plaintext, |b, pt| {
            let cipher = XChaCha20Poly1305::new((&KEY).into());
            let nonce = (&NONCE).into();
            b.iter(|| {
                let ct = cipher.encrypt(nonce, pt.as_slice()).unwrap();
                black_box(ct)
            });
        });

        // Ours (iter_batched separates clone from measured code)
        group.bench_with_input(BenchmarkId::new("memaead", size), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| black_box(xchacha20poly1305_encrypt(&KEY, &NONCE, AAD, &mut buf)),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        // Pre-encrypt with our implementation (both produce same output)
        let mut plaintext = vec![0xAB; size];
        let ciphertext = xchacha20poly1305_encrypt(&KEY, &NONCE, AAD, &mut plaintext);

        group.throughput(Throughput::Bytes(size as u64));

        // RustCrypto (traditional API)
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size),
            &ciphertext,
            |b, ct| {
                let cipher = XChaCha20Poly1305::new((&KEY).into());
                let nonce = (&NONCE).into();
                b.iter(|| {
                    let pt = cipher.decrypt(nonce, ct.as_slice()).unwrap();
                    black_box(pt)
                });
            },
        );

        // Ours (iter_batched separates clone from measured code)
        group.bench_with_input(BenchmarkId::new("memaead", size), &ciphertext, |b, ct| {
            b.iter_batched(
                || ct.as_slice().to_vec(),
                |mut buf| black_box(xchacha20poly1305_decrypt(&KEY, &NONCE, AAD, &mut buf).unwrap()),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
