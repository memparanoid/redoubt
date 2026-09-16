// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How fast XChaCha20-Poly1305 is, and what the assembly is worth.
//!
//! The cipher and the authenticator are measured on their own before the AEAD
//! that stands them together, because a number for the whole says nothing about
//! which half is slow. Each of the two runs twice, once through the portable
//! Rust and once through whatever the target has, so the difference is readable
//! rather than asserted.
//!
//! The AEAD itself has no such pair: it does not publish the choice, so what is
//! measured is what a caller gets.
//!
//! # What these numbers are not
//!
//! A comparison against anybody else's implementation. This one is scalar by
//! construction — no AVX, no NEON, one block at a time — so a vectorised
//! ChaCha20 is expected to be several times faster, and that trade is made on
//! purpose and not reopened here.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_aead_v2_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_aead_v2_core::consts::poly1305::{KEY_SIZE as POLY_KEY_SIZE, TAG_SIZE};
use redoubt_aead_v2_core::{AeadDecrypt, AeadEncrypt, Backend};
use redoubt_aead_xchachapoly1305::XChaCha20Poly1305;
use redoubt_chacha::xchacha20::XChaCha20;
use redoubt_poly1305::Poly1305;

/// One block, a page, and then sizes where the per-call cost has stopped
/// mattering and the loop is all that is left.
const SIZES: [usize; 5] = [64, 1024, 4096, 65536, 1_048_576];

/// Named so a report reads as a comparison rather than as two runs that happen
/// to be next to each other.
const BACKENDS: [(&str, Backend); 2] = [("rust", Backend::Rust), ("asm", Backend::Auto)];

fn key() -> [u8; KEY_SIZE] {
    core::array::from_fn(|at| 0x40 + at as u8)
}

fn nonce() -> [u8; XNONCE_SIZE] {
    [0x17; XNONCE_SIZE]
}

// ============================================================================
// XChaCha20::xor
// ============================================================================

fn bench_xchacha20_xor(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20/xor");

    let key = key();
    let nonce = nonce();

    for of in SIZES {
        let mut data = vec![0xAB_u8; of];

        group.throughput(Throughput::Bytes(of as u64));

        for (name, backend) in BACKENDS {
            let cipher = XChaCha20::with_backend(backend);

            group.bench_with_input(BenchmarkId::new(name, of), &of, |b, _| {
                b.iter(|| {
                    cipher.xor(black_box(&key), black_box(&nonce), 1, black_box(&mut data));
                });
            });
        }
    }

    group.finish();
}

// ============================================================================
// Poly1305::update
// ============================================================================

fn bench_poly1305_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly1305/tag");

    let key = [0x5E_u8; POLY_KEY_SIZE];

    for of in SIZES {
        let message = vec![0xAB_u8; of];

        group.throughput(Throughput::Bytes(of as u64));

        for (name, backend) in BACKENDS {
            group.bench_with_input(BenchmarkId::new(name, of), &of, |b, _| {
                b.iter(|| {
                    let mut poly = Poly1305::new(black_box(&key)).with_backend(backend);
                    let mut tag = [0_u8; TAG_SIZE];

                    poly.update(black_box(&message));
                    poly.finalize_mut(&mut tag);

                    tag
                });
            });
        }
    }

    group.finish();
}

// ============================================================================
// XChaCha20Poly1305::encrypt
// ============================================================================

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchachapoly1305/encrypt");

    let key = key();
    let nonce = nonce();
    let mut aead = XChaCha20Poly1305::new();

    for of in SIZES {
        let mut data = vec![0xAB_u8; of];
        let mut tag = [0_u8; TAG_SIZE];

        group.throughput(Throughput::Bytes(of as u64));

        group.bench_with_input(BenchmarkId::from_parameter(of), &of, |b, _| {
            b.iter(|| {
                aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(b""),
                    black_box(&mut data),
                    &mut tag,
                );
            });
        });
    }

    group.finish();
}

// ============================================================================
// XChaCha20Poly1305::decrypt
// ============================================================================

/// The trip back, which is the same work plus a tag that has to match.
fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchachapoly1305/decrypt");

    let key = key();
    let nonce = nonce();
    let mut aead = XChaCha20Poly1305::new();

    for of in SIZES {
        let mut data = vec![0xAB_u8; of];
        let mut tag = [0_u8; TAG_SIZE];

        aead.encrypt(&key, &nonce, b"", &mut data, &mut tag);

        let sealed = data.clone();

        group.throughput(Throughput::Bytes(of as u64));

        group.bench_with_input(BenchmarkId::from_parameter(of), &of, |b, _| {
            b.iter(|| {
                data.copy_from_slice(&sealed);

                aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(b""),
                    black_box(&mut data),
                    black_box(&tag),
                )
                .expect("the tag is the one encrypt just wrote");
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_xchacha20_xor,
    bench_poly1305_tag,
    bench_encrypt,
    bench_decrypt
);
criterion_main!(benches);
