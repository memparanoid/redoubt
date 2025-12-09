// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox integrated benchmarks: memvault CipherBox vs raw crypto libraries
//!
//! Compares full roundtrip: encode -> encrypt -> decrypt -> decode

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use memaead::Aead as MemAead;
use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};
use memvault_core::{
    CipherBox, CipherBoxError, DecryptStruct, Decryptable, EncryptStruct, Encryptable,
    decrypt_from, encrypt_into,
};
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

impl EncryptStruct<1> for Data2MB {
    fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn Encryptable; 1] {
        [&mut self.bytes]
    }

    fn encrypt_into(
        &mut self,
        aead: &mut MemAead,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; 1],
        tags: &mut [Vec<u8>; 1],
    ) -> Result<[Vec<u8>; 1], CipherBoxError> {
        encrypt_into(aead, aead_key, nonces, tags, self.to_encryptable_dyn_fields())
    }
}

impl DecryptStruct<1> for Data2MB {
    fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn Decryptable; 1] {
        [&mut self.bytes]
    }

    fn decrypt_from(
        &mut self,
        aead: &mut MemAead,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; 1],
        tags: &mut [Vec<u8>; 1],
        ciphertexts: &mut [Vec<u8>; 1],
    ) -> Result<(), CipherBoxError> {
        decrypt_from(aead, aead_key, nonces, tags, ciphertexts, self.to_decryptable_dyn_fields())
    }
}

fn bench_cipherbox_integrated(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_integrated");
    group.measurement_time(std::time::Duration::from_secs(5));
    group.sample_size(1000);
    // WalletSecrets: 32 + 32 + 64 + 32 = 160 bytes
    group.throughput(Throughput::Bytes(2 * 1024 * 1024));

    // === memvault CipherBox (full stack: HKDF + AEGIS-128L + memcodec + mprotect) ===
    {
        let mut cipherbox = CipherBox::<Data2MB, 1>::new();

        // Initialize
        // cipherbox
        //     .open_mut(|ws| {
        //         ws.master_seed = [0x42; 32];
        //         ws.encryption_key = [0xAB; 32];
        //         ws.signing_key = [0xCD; 64];
        //         ws.pin_hash = [0xEF; 32];
        //     })
        //     .unwrap();
        //
        //
        cipherbox
            .open_mut(|d| {
                d.bytes = vec![0xAB; 2 * 1024 * 1024];
            })
            .unwrap();

        group.bench_function("memvault_cipherbox", |b| {
            b.iter(|| {
                cipherbox
                    .open_mut(|ws| {
                        black_box(ws);
                        // ws.master_seed[0] = ws.master_seed[0].wrapping_add(1);
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

        let mut data = vec![0xABu8; 2 * 1024 * 1024];
        let mut ciphertext = cipher.encrypt(&nonce, data.as_slice()).unwrap();

        group.bench_function("xchacha20_hkdf_bincode", |b| {
            b.iter(|| {
                // Decrypt
                data = cipher.decrypt(&nonce, ciphertext.as_slice()).unwrap();

                // Modify
                data[0] = data[0].wrapping_add(1);

                // Encrypt
                ciphertext = cipher.encrypt(&nonce, data.as_slice()).unwrap();

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

        // Data2MBSerde for bincode (no DropSentinel)
        #[derive(Clone, Serialize, Deserialize)]
        struct Data2MBSerde {
            bytes: Vec<u8>,
        }

        let mut data = Data2MBSerde {
            bytes: vec![0xABu8; 2 * 1024 * 1024],
        };
        let encoded = bincode::serialize(&data).unwrap();
        let mut ciphertext = encoded;
        let state = Aegis128L::<16>::new(&nonce, &key);
        let mut tag = state.encrypt_in_place(&mut ciphertext, &[]);

        group.bench_function("aegis128l_hkdf_bincode", |b| {
            b.iter(|| {
                // Derive key
                let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut key = [0u8; 16];
                hk.expand(info, &mut key).unwrap();

                // Decrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                state.decrypt_in_place(&mut ciphertext, &tag, &[]).unwrap();

                // Decode
                data = bincode::deserialize(&ciphertext).unwrap();

                // Modify
                data.bytes[0] = data.bytes[0].wrapping_add(1);

                // Encode
                ciphertext = bincode::serialize(&data).unwrap();

                // Derive key again for encrypt
                let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut key = [0u8; 16];
                hk.expand(info, &mut key).unwrap();

                // Encrypt
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

        let mut data = Data2MB::new();

        let size = BytesRequired::mem_bytes_required(&data).unwrap();
        let mut encode_buf = CodecBuffer::new(size);
        data.encode_into(&mut encode_buf).unwrap();

        let mut ciphertext = encode_buf.as_slice().to_vec();
        let state = Aegis128L::<16>::new(&nonce, &key);
        let mut tag = state.encrypt_in_place(&mut ciphertext, &[]);

        group.bench_function("aegis128l_hkdf_memcodec", |b| {
            b.iter(|| {
                // Derive key
                let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut key = [0u8; 16];
                hk.expand(info, &mut key).unwrap();

                // Decrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                state.decrypt_in_place(&mut ciphertext, &tag, &[]).unwrap();

                // Decode
                let mut decoded = Data2MB::default();
                decoded.decode_from(&mut ciphertext.as_mut_slice()).unwrap();

                // Modify
                decoded.bytes[0] = decoded.bytes[0].wrapping_add(1);

                // Encode
                let mut encode_buf = CodecBuffer::new(size);
                decoded.encode_into(&mut encode_buf).unwrap();
                ciphertext.clear();
                ciphertext.extend_from_slice(encode_buf.as_slice());

                // Derive key again for encrypt
                let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut key = [0u8; 16];
                hk.expand(info, &mut key).unwrap();

                // Encrypt
                let state = Aegis128L::<16>::new(&nonce, &key);
                tag = state.encrypt_in_place(&mut ciphertext, &[]);

                black_box(())
            });
        });
    }

    group.finish();
}

fn bench_zeroize_2mb(c: &mut Criterion) {
    use memzer::FastZeroizable;

    let mut group = c.benchmark_group("zeroize");
    group.throughput(Throughput::Bytes(2 * 1024 * 1024));

    group.bench_function("2mb_struct", |b| {
        let mut data = Data2MB::new();
        b.iter(|| {
            data.fast_zeroize();
            black_box(&data);
        });
    });

    group.bench_function("2mb_vec_raw", |b| {
        let mut data = vec![0xABu8; 2 * 1024 * 1024];
        b.iter(|| {
            data.fast_zeroize();
            black_box(&data);
        });
    });

    group.finish();
}

fn bench_clone_2mb(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone");
    group.throughput(Throughput::Bytes(2 * 1024 * 1024));

    group.bench_function("2mb_vec", |b| {
        let data = vec![0xABu8; 2 * 1024 * 1024];
        b.iter(|| {
            let cloned = data.clone();
            black_box(cloned)
        });
    });

    group.finish();
}

fn bench_primitives(c: &mut Criterion) {
    use memaead::Aead;
    use memvault_core::leak_master_key;

    let mut group = c.benchmark_group("primitives");

    group.bench_function("aead_generate_nonce", |b| {
        let mut aead = Aead::new();
        b.iter(|| {
            let nonce = aead.generate_nonce().unwrap();
            black_box(nonce)
        });
    });

    group.bench_function("leak_master_key", |b| {
        b.iter(|| {
            let key = leak_master_key(16).unwrap();
            black_box(key)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cipherbox_integrated,
    bench_zeroize_2mb,
    bench_clone_2mb,
    bench_primitives
);
criterion_main!(benches);
