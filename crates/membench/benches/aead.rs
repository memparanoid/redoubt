// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD benchmarks: memaead vs RustCrypto chacha20poly1305 vs AEGIS variants
//!
//! Compares the "traditional" allocating API that most users use.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

// RustCrypto ChaCha20-Poly1305
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};

// AEGIS
use aegis::aegis128l::Aegis128L;
use aegis::aegis128x4::Aegis128X4;
use aegis::aegis256::Aegis256;

// Ours
use memaead::Aead as MemAead;

const KEY: [u8; 32] = [0x42; 32];
const KEY_16: [u8; 16] = [0x42; 16];
const NONCE: [u8; 24] = [0x24; 24];
const NONCE_32: [u8; 32] = [0x24; 32];
const NONCE_16: [u8; 16] = [0x24; 16];
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
            let mut aead = MemAead::new();
            let key = &KEY[..aead.key_size()];
            let nonce = &NONCE[..aead.nonce_size()];
            let tag_size = aead.tag_size();
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    let mut tag = vec![0u8; tag_size];
                    aead.encrypt(key, nonce, AAD, &mut buf, &mut tag)
                        .expect("Failed to encrypt(..)");
                    black_box((buf, tag))
                },
                BatchSize::SmallInput,
            );
        });

        // AEGIS-128L (hardware accelerated, 128-bit key, optimized for long messages)
        group.bench_with_input(BenchmarkId::new("aegis128l", size), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    let state = Aegis128L::<16>::new(&NONCE_16, &KEY_16);
                    let tag = state.encrypt_in_place(&mut buf, &[]);
                    black_box((buf, tag))
                },
                BatchSize::SmallInput,
            );
        });

        // AEGIS-128X4 (4-way parallel, 128-bit key)
        group.bench_with_input(BenchmarkId::new("aegis128x4", size), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    let state = Aegis128X4::<16>::new(&NONCE_16, &KEY_16);
                    let tag = state.encrypt_in_place(&mut buf, &[]);
                    black_box((buf, tag))
                },
                BatchSize::SmallInput,
            );
        });

        // AEGIS-256 (hardware accelerated, 256-bit key)
        group.bench_with_input(BenchmarkId::new("aegis256", size), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    let state = Aegis256::<16>::new(&NONCE_32, &KEY);
                    let tag = state.encrypt_in_place(&mut buf, &[]);
                    black_box((buf, tag))
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        // Pre-encrypt with our implementation
        let mut aead_setup = MemAead::new();
        let key = &KEY[..aead_setup.key_size()];
        let nonce = &NONCE[..aead_setup.nonce_size()];
        let tag_size = aead_setup.tag_size();

        let mut plaintext = vec![0xAB; size];
        let mut our_tag = vec![0u8; tag_size];
        aead_setup
            .encrypt(key, nonce, AAD, &mut plaintext, &mut our_tag)
            .expect("Failed to encrypt(..)");
        let our_ciphertext = plaintext; // now contains ciphertext

        // RustCrypto needs ciphertext || tag format
        let mut rustcrypto_ct = our_ciphertext.clone();
        rustcrypto_ct.extend_from_slice(&our_tag);

        group.throughput(Throughput::Bytes(size as u64));

        // RustCrypto (traditional API)
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size),
            &rustcrypto_ct,
            |b, ct| {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new((&KEY).into());
                let nonce = (&NONCE).into();
                b.iter(|| {
                    let pt = cipher.decrypt(nonce, ct.as_slice()).unwrap();
                    black_box(pt)
                });
            },
        );

        // Ours (iter_batched separates clone from measured code)
        group.bench_with_input(
            BenchmarkId::new("memaead", size),
            &(our_ciphertext.clone(), our_tag.clone()),
            |b, (ct, tag)| {
                let mut aead = MemAead::new();
                let key = &KEY[..aead.key_size()];
                let nonce = &NONCE[..aead.nonce_size()];
                b.iter_batched(
                    || ct.clone(),
                    |mut buf| {
                        aead.decrypt(key, nonce, AAD, &mut buf, tag)
                            .expect("Failed to decrypt(..)");
                        black_box(buf)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // AEGIS-128L decrypt (hardware accelerated, 128-bit key, optimized for long messages)
        // Pre-encrypt with AEGIS-128L
        let mut aegis128l_plaintext = vec![0xAB; size];
        let aegis128l_state = Aegis128L::<16>::new(&NONCE_16, &KEY_16);
        let aegis128l_tag = aegis128l_state.encrypt_in_place(&mut aegis128l_plaintext, &[]);
        let aegis128l_ciphertext = aegis128l_plaintext;

        group.bench_with_input(
            BenchmarkId::new("aegis128l", size),
            &(aegis128l_ciphertext.clone(), aegis128l_tag),
            |b, (ct, tag): &(Vec<u8>, [u8; 16])| {
                b.iter_batched(
                    || ct.clone(),
                    |mut buf| {
                        let state = Aegis128L::<16>::new(&NONCE_16, &KEY_16);
                        state.decrypt_in_place(&mut buf, tag, &[]).unwrap();
                        black_box(buf)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // AEGIS-128X4 decrypt (4-way parallel, 128-bit key)
        // Pre-encrypt with AEGIS-128X4
        let mut aegis128x4_plaintext = vec![0xAB; size];
        let aegis128x4_state = Aegis128X4::<16>::new(&NONCE_16, &KEY_16);
        let aegis128x4_tag = aegis128x4_state.encrypt_in_place(&mut aegis128x4_plaintext, &[]);
        let aegis128x4_ciphertext = aegis128x4_plaintext;

        group.bench_with_input(
            BenchmarkId::new("aegis128x4", size),
            &(aegis128x4_ciphertext.clone(), aegis128x4_tag),
            |b, (ct, tag): &(Vec<u8>, [u8; 16])| {
                b.iter_batched(
                    || ct.clone(),
                    |mut buf| {
                        let state = Aegis128X4::<16>::new(&NONCE_16, &KEY_16);
                        state.decrypt_in_place(&mut buf, tag, &[]).unwrap();
                        black_box(buf)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // AEGIS-256 decrypt (hardware accelerated, 256-bit key)
        // Pre-encrypt with AEGIS-256
        let mut aegis256_plaintext = vec![0xAB; size];
        let aegis256_state = Aegis256::<16>::new(&NONCE_32, &KEY);
        let aegis256_tag = aegis256_state.encrypt_in_place(&mut aegis256_plaintext, &[]);
        let aegis256_ciphertext = aegis256_plaintext;

        group.bench_with_input(
            BenchmarkId::new("aegis256", size),
            &(aegis256_ciphertext.clone(), aegis256_tag),
            |b, (ct, tag): &(Vec<u8>, [u8; 16])| {
                b.iter_batched(
                    || ct.clone(),
                    |mut buf| {
                        let state = Aegis256::<16>::new(&NONCE_32, &KEY);
                        state.decrypt_in_place(&mut buf, tag, &[]).unwrap();
                        black_box(buf)
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
