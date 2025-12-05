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

use memaead::Aead as MemAead;

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

    group.bench_with_input(
        BenchmarkId::new("memaead", size),
        &plaintext,
        |b, pt| {
            let mut aead = MemAead::new();
            let key = &KEY_16[..aead.key_size()];
            let nonce = &NONCE_16[..aead.nonce_size()];
            let tag_size = aead.tag_size();
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    let mut tag = vec![0u8; tag_size];
                    aead.encrypt(key, nonce, &[], &mut buf, &mut tag);
                    black_box((buf, tag))
                },
                BatchSize::LargeInput,
            );
        },
    );

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

    // Pre-encrypt with memaead
    let mut memaead_aead_setup = MemAead::new();
    let key = &KEY_16[..memaead_aead_setup.key_size()];
    let nonce = &NONCE_16[..memaead_aead_setup.nonce_size()];
    let tag_size = memaead_aead_setup.tag_size();

    let mut memaead_plaintext = vec![0xAB; size];
    let mut memaead_tag = vec![0u8; tag_size];
    memaead_aead_setup.encrypt(key, nonce, &[], &mut memaead_plaintext, &mut memaead_tag);
    let memaead_ciphertext = memaead_plaintext;

    group.bench_with_input(
        BenchmarkId::new("memaead", size),
        &(memaead_ciphertext.clone(), memaead_tag.clone()),
        |b, (ct, tag)| {
            let mut aead = MemAead::new();
            let key = &KEY_16[..aead.key_size()];
            let nonce = &NONCE_16[..aead.nonce_size()];
            b.iter_batched(
                || ct.clone(),
                |mut buf| {
                    aead.decrypt(key, nonce, &[], &mut buf, tag).unwrap();
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
