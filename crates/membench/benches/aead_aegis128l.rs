// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L vs AEGIS-128X4 benchmark at 2MB
//!
//! Head-to-head comparison for realistic payload sizes.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use aegis::aegis128l::Aegis128L;
use aegis::aegis128x4::Aegis128X4;

const KEY_16: [u8; 16] = [0x42; 16];
const NONCE_16: [u8; 16] = [0x24; 16];

fn bench_encrypt_2mb(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_2mb");

    let size = 2 * 1024 * 1024; // 2MB
    let plaintext = vec![0xAB; size];

    group.throughput(Throughput::Bytes(size as u64));

    group.bench_with_input(BenchmarkId::new("aegis128l", size), &plaintext, |b, pt| {
        b.iter_batched(
            || pt.clone(),
            |mut buf| {
                let state = Aegis128L::<16>::new(&NONCE_16, &KEY_16);
                let tag = state.encrypt_in_place(&mut buf, &[]);
                black_box((buf, tag))
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_with_input(BenchmarkId::new("aegis128x4", size), &plaintext, |b, pt| {
        b.iter_batched(
            || pt.clone(),
            |mut buf| {
                let state = Aegis128X4::<16>::new(&NONCE_16, &KEY_16);
                let tag = state.encrypt_in_place(&mut buf, &[]);
                black_box((buf, tag))
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_decrypt_2mb(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_2mb");

    let size = 2 * 1024 * 1024; // 2MB

    group.throughput(Throughput::Bytes(size as u64));

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
                BatchSize::LargeInput,
            );
        },
    );

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
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

criterion_group!(benches, bench_encrypt_2mb, bench_decrypt_2mb);
criterion_main!(benches);
