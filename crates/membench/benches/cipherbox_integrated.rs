// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox integrated benchmarks: memvault CipherBox vs raw crypto libraries
//!
//! Compares full roundtrip: encode -> encrypt -> decrypt -> decode

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};
use memvault_core::CipherBox;
use memzer::{DropSentinel, FastZeroizable, MemZer};

// Shared struct for all benchmarks
#[derive(MemZer, Codec, Clone)]
#[memzer(drop)]
pub struct WalletSecrets {
    master_seed: [u8; 32],
    encryption_key: [u8; 32],
    signing_key: [u8; 64],
    pin_hash: [u8; 32],
    #[codec(default)]
    __drop_sentinel: DropSentinel,
}

impl Default for WalletSecrets {
    fn default() -> Self {
        Self {
            master_seed: [0u8; 32],
            encryption_key: [0u8; 32],
            signing_key: [0u8; 64],
            pin_hash: [0u8; 32],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

// For serde/bincode comparison (serde doesn't support [u8; 64] out of the box)
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
pub struct WalletSecretsSerde {
    master_seed: [u8; 32],
    encryption_key: [u8; 32],
    signing_key_1: [u8; 32],
    signing_key_2: [u8; 32],
    pin_hash: [u8; 32],
}

impl WalletSecretsSerde {
    fn sample() -> Self {
        Self {
            master_seed: [0x42; 32],
            encryption_key: [0xAB; 32],
            signing_key_1: [0xCD; 32],
            signing_key_2: [0xCD; 32],
            pin_hash: [0xEF; 32],
        }
    }
}

fn bench_cipherbox_integrated(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_integrated");
    group.measurement_time(std::time::Duration::from_secs(5));
    group.sample_size(1000);
    // WalletSecrets: 32 + 32 + 64 + 32 = 160 bytes
    group.throughput(Throughput::Bytes(160));

    // === memvault CipherBox (full stack: HKDF + AEGIS-128L + memcodec + mprotect) ===
    {
        let mut cipherbox = CipherBox::<WalletSecrets>::new();

        // Initialize
        cipherbox
            .open_mut(|ws| {
                ws.master_seed = [0x42; 32];
                ws.encryption_key = [0xAB; 32];
                ws.signing_key = [0xCD; 64];
                ws.pin_hash = [0xEF; 32];
            })
            .unwrap();

        group.bench_function("memvault_cipherbox", |b| {
            b.iter(|| {
                cipherbox
                    .open_mut(|ws| {
                        ws.master_seed[0] = ws.master_seed[0].wrapping_add(1);
                    })
                    .unwrap();
                black_box(())
            });
        });
    }

    // === chacha20poly1305 + hkdf + bincode ===
    {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            XChaCha20Poly1305, XNonce,
        };
        use hkdf::Hkdf;
        use sha2::Sha256;

        let ikm = [0x42u8; 32];
        let salt = [0x24u8; 16];
        let info = b"bench";

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key).unwrap();

        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = XNonce::try_from([0u8; 24]).unwrap();

        let mut data = WalletSecretsSerde::sample();
        let encoded = bincode::serialize(&data).unwrap();
        let mut ciphertext = cipher.encrypt(&nonce, encoded.as_slice()).unwrap();

        group.bench_function("xchacha20_hkdf_bincode", |b| {
            b.iter(|| {
                // Decrypt
                let plaintext = cipher.decrypt(&nonce, ciphertext.as_slice()).unwrap();

                // Decode
                data = bincode::deserialize(&plaintext).unwrap();

                // Modify
                data.master_seed[0] = data.master_seed[0].wrapping_add(1);

                // Encode
                let encoded = bincode::serialize(&data).unwrap();

                // Encrypt
                ciphertext = cipher.encrypt(&nonce, encoded.as_slice()).unwrap();

                black_box(())
            });
        });
    }

    // === aegis-128l + hkdf + bincode ===
    {
        use aegis::aegis128l::Aegis128L;
        use hkdf::Hkdf;
        use sha2::Sha256;

        let ikm = [0x42u8; 32];
        let salt = [0x24u8; 16];
        let info = b"bench";

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut key = [0u8; 16];
        hk.expand(info, &mut key).unwrap();

        let nonce = [0u8; 16];

        let mut data = WalletSecretsSerde::sample();
        let encoded = bincode::serialize(&data).unwrap();
        let mut ciphertext = encoded.clone();
        let state = Aegis128L::<16>::new(&nonce, &key);
        let mut tag = state.encrypt_in_place(&mut ciphertext, &[]);

        group.bench_function("aegis128l_hkdf_bincode", |b| {
            b.iter(|| {
                // Decrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                state.decrypt_in_place(&mut ciphertext, &tag, &[]).unwrap();

                // Decode
                data = bincode::deserialize(&ciphertext).unwrap();

                // Modify
                data.master_seed[0] = data.master_seed[0].wrapping_add(1);

                // Encode + Encrypt
                ciphertext = bincode::serialize(&data).unwrap();
                let state = Aegis128L::<16>::new(&nonce, &key);
                tag = state.encrypt_in_place(&mut ciphertext, &[]);

                black_box(())
            });
        });
    }

    // === aegis-128l + hkdf + memcodec ===
    {
        use aegis::aegis128l::Aegis128L;
        use hkdf::Hkdf;
        use sha2::Sha256;

        let ikm = [0x42u8; 32];
        let salt = [0x24u8; 16];
        let info = b"bench";

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut key = [0u8; 16];
        hk.expand(info, &mut key).unwrap();

        let nonce = [0u8; 16];

        let mut data = WalletSecrets::default();
        data.master_seed = [0x42; 32];
        data.encryption_key = [0xAB; 32];
        data.signing_key = [0xCD; 64];
        data.pin_hash = [0xEF; 32];

        let size = BytesRequired::mem_bytes_required(&data).unwrap();
        let mut encode_buf = CodecBuffer::new(size);
        data.encode_into(&mut encode_buf).unwrap();

        let mut ciphertext = encode_buf.as_slice().to_vec();
        let state = Aegis128L::<16>::new(&nonce, &key);
        let mut tag = state.encrypt_in_place(&mut ciphertext, &[]);

        group.bench_function("aegis128l_hkdf_memcodec", |b| {
            b.iter(|| {
                // Decrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                state.decrypt_in_place(&mut ciphertext, &tag, &[]).unwrap();

                // Decode
                let mut decoded = WalletSecrets::default();
                decoded.decode_from(&mut ciphertext.as_mut_slice()).unwrap();

                // Modify
                decoded.master_seed[0] = decoded.master_seed[0].wrapping_add(1);

                // Encode
                let mut encode_buf = CodecBuffer::new(size);
                decoded.encode_into(&mut encode_buf).unwrap();
                ciphertext.clear();
                ciphertext.extend_from_slice(encode_buf.as_slice());

                // Encrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                tag = state.encrypt_in_place(&mut ciphertext, &[]);

                black_box(())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cipherbox_integrated);
criterion_main!(benches);
