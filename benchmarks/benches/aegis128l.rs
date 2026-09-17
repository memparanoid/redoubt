// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How fast AEGIS-128L is.
//!
//! There is one pair of numbers here and not two. The other AEAD in this
//! workspace publishes its backend, so it can be run twice and the assembly
//! read against the Rust; this one has no Rust to run — AEGIS *is* the AES
//! round function, and a portable version would be a different algorithm with
//! the same name. What is measured is what a caller gets, on a machine that
//! has the instructions.
//!
//! # What the number is for
//!
//! The comparison that matters is against `xchachapoly1305`, measured beside
//! this. Both are AEADs this workspace ships, and the whole reason to have two
//! is that they are not the same trade: one is scalar by construction and
//! portable, the other is an AES-NI instruction sequence and is not.
//!
//! # Encrypting and deciphering are the same walk
//!
//! One pass over the state either way, so the two groups are expected to agree
//! within noise. They are both here because a divergence would mean the tag
//! comparison or the wipe on the refusing path had started to cost something,
//! and neither should.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_aead_aegis128l::Aegis128L;
use redoubt_aead_v2_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_v2_core::{AeadDecrypt, AeadEncrypt};

/// One block, a page, and then sizes where the per-call cost has stopped
/// mattering and the loop is all that is left.
const SIZES: [usize; 5] = [64, 1024, 4096, 65536, 1_048_576];

fn key() -> [u8; KEY_SIZE] {
    core::array::from_fn(|at| 0x40 + at as u8)
}

fn nonce() -> [u8; NONCE_SIZE] {
    [0x17; NONCE_SIZE]
}

// ============================================================================
// Aegis128L::encrypt
// ============================================================================

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aegis128l/encrypt");

    let key = key();
    let nonce = nonce();
    let mut aead = Aegis128L::new();

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
// Aegis128L::decrypt
// ============================================================================

/// The trip back, which is the same walk plus a tag that has to match.
///
/// The ciphertext is put back before each iteration, because deciphering it
/// leaves the plaintext where it was and a second pass would be measuring the
/// wrong bytes.
fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aegis128l/decrypt");

    let key = key();
    let nonce = nonce();
    let mut aead = Aegis128L::new();

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

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
