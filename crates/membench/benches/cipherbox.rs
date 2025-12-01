// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox benchmarks: full roundtrip (decrypt -> deserialize -> serialize -> encrypt)
//!
//! Compares memcode + chacha20poly1305 vs memcodec + aegis128l on 2MB payload.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use membuffer::Buffer;
use memcode::{MemBytesRequired, MemCodec, MemDecode, MemEncode, MemEncodeBuf};
use memcodec::{BytesRequired, Codec, Decode, Encode};

use memaead::xchacha20poly1305::XChacha20Poly1305;
use memaead::Aead;
use memaead::Aegis128L;

const KEY_32: [u8; 32] = [0x42; 32];
const KEY_16: [u8; 16] = [0x42; 16];
const NONCE_24: [u8; 24] = [0x24; 24];
const NONCE_16: [u8; 16] = [0x24; 16];
const AAD: &[u8] = b"";

// === 2MB struct ===

#[derive(Clone, Default, Serialize, Deserialize, Zeroize, MemCodec, Codec)]
struct Data2MB {
    bytes: Vec<u8>,
}

impl Data2MB {
    fn new() -> Self {
        Self {
            bytes: vec![0xAB; 2 * 1024 * 1024],
        }
    }

    fn empty() -> Self {
        Self { bytes: Vec::new() }
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

    // === memcode + chacha ===
    {
        let mut data = Data2MB::new();
        let mut chacha = XChacha20Poly1305::default();

        let size = MemBytesRequired::mem_bytes_required(&data).unwrap();
        let mut encode_buf = MemEncodeBuf::new(size);
        data.drain_into(&mut encode_buf).unwrap();

        let mut ct = encode_buf.as_slice().to_vec();
        let mut tag = [0u8; 16];
        chacha.encrypt(&KEY_32, &NONCE_24, AAD, &mut ct, &mut tag);

        group.bench_function("memcode_chacha", |b| {
            b.iter(|| {
                // Decrypt
                chacha
                    .decrypt(&KEY_32, &NONCE_24, AAD, &mut ct, &tag)
                    .unwrap();

                // Deserialize
                let mut decoded = Data2MB::empty();
                decoded.drain_from(&mut ct).unwrap();
                data = decoded;

                // Serialize (overwrite ct with encoded data)
                let mut encode_buf = MemEncodeBuf::new(size);
                data.drain_into(&mut encode_buf).unwrap();
                ct.clear();
                ct.extend_from_slice(encode_buf.as_slice());

                // Encrypt
                chacha.encrypt(&KEY_32, &NONCE_24, AAD, &mut ct, &mut tag);

                black_box(ct.len())
            });
        });
    }

    // === memcodec + aegis128l ===
    {
        let mut data = Data2MB::new();
        let size = BytesRequired::mem_bytes_required(&data).unwrap();
        let mut encode_buf = Buffer::new(size);
        data.encode_into(&mut encode_buf).unwrap();

        let mut ct = encode_buf.as_slice().to_vec();
        let mut tag = [0u8; 16];
        let mut aegis = Aegis128L::default();
        aegis.encrypt(&KEY_16, &NONCE_16, AAD, &mut ct, &mut tag);

        group.bench_function("memcodec_aegis128l", |b| {
            b.iter(|| {
                // Decrypt
                aegis
                    .decrypt(&KEY_16, &NONCE_16, AAD, &mut ct, &tag)
                    .unwrap();

                // Deserialize
                let mut decoded = Data2MB::empty();
                decoded.decode_from(&mut ct.as_mut_slice()).unwrap();
                data = decoded;

                // Serialize (overwrite ct with encoded data)
                let mut encode_buf = Buffer::new(size);
                data.encode_into(&mut encode_buf).unwrap();
                ct.clear();
                ct.extend_from_slice(encode_buf.as_slice());

                // Encrypt
                aegis.encrypt(&KEY_16, &NONCE_16, AAD, &mut ct, &mut tag);

                black_box(ct.len())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cipherbox);
criterion_main!(benches);
