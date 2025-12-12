// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox benchmarks: full roundtrip (decrypt -> deserialize -> serialize -> encrypt)
//!
//! Benchmarks memcodec + aegis128l on 2MB payload.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};

use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};
use memzer::{DropSentinel, FastZeroizable, MemZer};

use memaead::Aead;

const KEY_16: [u8; 16] = [0x42; 16];
const NONCE_16: [u8; 16] = [0x24; 16];
const AAD: &[u8] = b"";

// === 2MB struct ===

#[derive(Clone, Serialize, Deserialize, Codec, MemZer)]
#[memzer(drop)]
struct Data2MB {
    bytes: Vec<u8>,
    #[serde(skip)]
    #[codec(default)]
    __drop_sentinel: DropSentinel,
}

impl Default for Data2MB {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl Data2MB {
    fn new() -> Self {
        Self {
            bytes: vec![0xAB; 2 * 1024 * 1024],
            __drop_sentinel: DropSentinel::default(),
        }
    }

    fn empty() -> Self {
        Self::default()
    }

    fn total_bytes() -> usize {
        2 * 1024 * 1024
    }
}

fn bench_cipherbox(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_roundtrip");
    group.measurement_time(std::time::Duration::from_secs(5));
    group.sample_size(100);

    let total_bytes = Data2MB::total_bytes();
    group.throughput(Throughput::Bytes(total_bytes as u64));

    // === memcodec + aead ===
    {
        let mut data = Data2MB::new();
        let size = BytesRequired::mem_bytes_required(&data).unwrap();
        let mut encode_buf = CodecBuffer::new(size);
        data.encode_into(&mut encode_buf).unwrap();

        let mut aead = Aead::new();
        let key = &KEY_16[..aead.key_size()];
        let nonce = &NONCE_16[..aead.nonce_size()];
        let tag_size = aead.tag_size();

        let mut ct = encode_buf.to_vec();
        let mut tag = vec![0u8; tag_size];
        aead.encrypt(key, nonce, AAD, &mut ct, &mut tag)
            .expect("Failed to encrypt(..)");

        group.bench_function("memcodec_aead", |b| {
            b.iter(|| {
                // Decrypt
                aead.decrypt(key, nonce, AAD, &mut ct, &tag)
                    .expect("Failed to decrypt(..)");

                // Deserialize
                let mut decoded = Data2MB::empty();
                decoded.decode_from(&mut ct.as_mut_slice()).unwrap();
                data = decoded;

                // Serialize (overwrite ct with encoded data)
                let size = BytesRequired::mem_bytes_required(&data).unwrap();
                let mut encode_buf = CodecBuffer::new(size);
                data.encode_into(&mut encode_buf).unwrap();
                ct = encode_buf.to_vec();

                // Encrypt
                aead.encrypt(key, nonce, AAD, &mut ct, &mut tag)
                    .expect("Failed to encrypt(..)");

                black_box(ct.len())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cipherbox);
criterion_main!(benches);
