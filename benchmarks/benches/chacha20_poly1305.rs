// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Benchmark for ChaCha20 + Poly1305 (SSH-style usage).
//!
//! Simulates encrypting 20MB in 4KB chunks using Bernstein ChaCha20 (8-byte nonce)
//! with Poly1305 MAC — the same construction used by chacha20-poly1305@openssh.com.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use redoubt_aead_xchacha::{ChaCha20, Poly1305, CHACHA20_BERNSTEIN_NONCE_SIZE};

const CHUNK_SIZE: usize = 4096;
const TOTAL_SIZE: usize = 20 * 1024 * 1024; // 20 MB
const NUM_CHUNKS: usize = TOTAL_SIZE / CHUNK_SIZE;

fn bench_chacha20_bernstein_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let mut data = vec![0xABu8; CHUNK_SIZE];

    let mut group = c.benchmark_group("chacha20_bernstein");
    group.throughput(Throughput::Bytes(TOTAL_SIZE as u64));

    group.bench_function("encrypt_20mb_4kb_chunks", |b| {
        b.iter(|| {
            let mut chacha = ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default();

            for i in 0..NUM_CHUNKS {
                chacha.crypt(
                    black_box(&key),
                    black_box(&nonce),
                    i as u64,
                    black_box(&mut data),
                );
            }
        });
    });

    group.finish();
}

fn bench_chacha20_poly1305_encrypt(c: &mut Criterion) {
    let main_key = [0x42u8; 32];
    let header_key = [0x43u8; 32];
    let mut data = vec![0xABu8; CHUNK_SIZE];
    let mut length_bytes = [0u8; 4];

    let mut group = c.benchmark_group("chacha20_poly1305_ssh");
    group.throughput(Throughput::Bytes(TOTAL_SIZE as u64));

    group.bench_function("encrypt_20mb_4kb_chunks", |b| {
        b.iter(|| {
            let mut chacha = ChaCha20::<CHACHA20_BERNSTEIN_NONCE_SIZE>::default();

            for seq in 0..NUM_CHUNKS {
                let nonce = (seq as u64).to_be_bytes();

                // 1. Encrypt packet length with header key
                length_bytes = (CHUNK_SIZE as u32).to_be_bytes();
                chacha.crypt(
                    black_box(&header_key),
                    black_box(&nonce),
                    0,
                    black_box(&mut length_bytes),
                );

                // 2. Generate poly1305 key
                let mut poly_key = [0u8; 32];
                chacha.crypt(
                    black_box(&main_key),
                    black_box(&nonce),
                    0,
                    black_box(&mut poly_key),
                );

                // 3. Encrypt payload
                chacha.crypt(
                    black_box(&main_key),
                    black_box(&nonce),
                    1,
                    black_box(&mut data),
                );

                // 4. Compute MAC
                let mut mac = [0u8; 16];
                Poly1305::compute(
                    black_box(&poly_key),
                    black_box(&data),
                    black_box(&mut mac),
                );
            }
        });
    });

    group.finish();
}

fn bench_chacha20_ietf_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let mut data = vec![0xABu8; CHUNK_SIZE];

    let mut group = c.benchmark_group("chacha20_ietf");
    group.throughput(Throughput::Bytes(TOTAL_SIZE as u64));

    group.bench_function("encrypt_20mb_4kb_chunks", |b| {
        b.iter(|| {
            let mut chacha = ChaCha20::<12>::default();

            for i in 0..NUM_CHUNKS {
                chacha.crypt(
                    black_box(&key),
                    black_box(&nonce),
                    i as u64,
                    black_box(&mut data),
                );
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_chacha20_bernstein_encrypt,
    bench_chacha20_poly1305_encrypt,
    bench_chacha20_ietf_encrypt,
);
criterion_main!(benches);
