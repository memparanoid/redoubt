// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcodec::Codec;
use memzer::{DropSentinel, FastZeroizable, MemZer, ZeroizationProbe};

use crate::cipherbox::CipherBox;
use crate::master_key::open;

#[derive(MemZer, Codec)]
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

#[test]
fn test_wallet_secrets() {
    let mut wallet_secrets_box = CipherBox::<WalletSecrets>::new();

    wallet_secrets_box
        .open(|ws| {
            assert!(ws.master_seed.is_zeroized());
            assert!(ws.encryption_key.is_zeroized());
            assert!(ws.signing_key.is_zeroized());
            assert!(ws.pin_hash.is_zeroized());
        })
        .expect("Failed to open(..)");

    wallet_secrets_box
        .open_mut(|ws| {
            ws.master_seed = [0x42; 32];
            ws.encryption_key = [0xAB; 32];
            ws.signing_key = [0xCD; 64];
            ws.pin_hash = [0xEF; 32];
        })
        .expect("Failed to open_mut(..)");

    wallet_secrets_box
        .open(|ws| {
            assert_eq!(ws.master_seed, [0x42; 32]);
            assert_eq!(ws.encryption_key, [0xAB; 32]);
            assert_eq!(ws.signing_key, [0xCD; 64]);
            assert_eq!(ws.pin_hash, [0xEF; 32]);
        })
        .expect("Failed to open(..)");
}

// #[test]
// fn bench_wallet_secrets_cipherbox() {
//     use std::time::Instant;

//     let mut wallet_secrets_box = CipherBox::<WalletSecrets>::new();

//     // Warmup
//     for _ in 0..1000 {
//         wallet_secrets_box.open(|_| {}).unwrap();
//         wallet_secrets_box
//             .open_mut(|ws| {
//                 ws.master_seed[0] = 0;
//             })
//             .unwrap();
//     }

//     // Bench open (read-only)
//     let iterations = 10_000;
//     let start = Instant::now();
//     for _ in 0..iterations {
//         wallet_secrets_box.open(|_| {}).expect("open failed");
//     }
//     let elapsed = start.elapsed();
//     let per_op_ns = elapsed.as_nanos() / iterations as u128;
//     println!(
//         "open(): {} ns/op ({} ops/sec)",
//         per_op_ns,
//         1_000_000_000 / per_op_ns
//     );

//     // Bench open_mut (read + write)
//     let start = Instant::now();
//     for _ in 0..iterations {
//         wallet_secrets_box
//             .open_mut(|ws| {
//                 ws.master_seed[0] = ws.master_seed[0].wrapping_add(1);
//             })
//             .expect("open_mut failed");
//     }
//     let elapsed = start.elapsed();
//     let per_op_ns = elapsed.as_nanos() / iterations as u128;
//     println!(
//         "open_mut(): {} ns/op ({} ops/sec)",
//         per_op_ns,
//         1_000_000_000 / per_op_ns
//     );
// }

// #[test]
// fn bench_cipherbox_pieces() {
//     use std::time::Instant;

//     let mut box_ = CipherBox::<WalletSecrets>::new();
//     box_.maybe_initialize().unwrap();

//     let mut wallet_secrets_box = CipherBox::<WalletSecrets>::new();

//     // Warmup
//     for _ in 0..1000 {
//         wallet_secrets_box.open(|_| {}).unwrap();
//         wallet_secrets_box
//             .open_mut(|ws| {
//                 ws.master_seed[0] = 0;
//             })
//             .unwrap();
//     }

//     let iterations = 10_000;

//     // 1. derive_key solo
//     let start = Instant::now();
//     for _ in 0..iterations {
//         let mut key = box_.derive_key().unwrap();
//         key.fast_zeroize();
//     }
//     let elapsed = start.elapsed();
//     println!(
//         "derive_key(): {} ns/op",
//         elapsed.as_nanos() / iterations as u128
//     );

//     // 2. decrypt solo (incluye derive_key)
//     let start = Instant::now();
//     for _ in 0..iterations {
//         let mut val = box_.decrypt().unwrap();
//         val.fast_zeroize();
//     }
//     let elapsed = start.elapsed();
//     println!(
//         "decrypt(): {} ns/op",
//         elapsed.as_nanos() / iterations as u128
//     );

//     // 3. encrypt solo (incluye derive_key)
//     let start = Instant::now();
//     for _ in 0..iterations {
//         let mut val = WalletSecrets::default();
//         box_.encrypt(&mut val).unwrap();
//     }
//     let elapsed = start.elapsed();
//     println!(
//         "encrypt(): {} ns/op",
//         elapsed.as_nanos() / iterations as u128
//     );
// }

#[test]
fn bench_2abc1_open() {
    use memhkdf::hkdf;
    use std::time::Instant;

    let mut box_ = CipherBox::<WalletSecrets>::new();
    box_.maybe_initialize().unwrap();

    let iterations = 10_000;

    // 1. master_key::open() solo
    for _ in 0..1000 {
        open(&mut |_ikm| Ok(())).unwrap();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        open(&mut |_ikm| Ok(())).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "master_key::open(): {} ns/op",
        elapsed.as_nanos() / iterations as u128
    );

    // 2. HKDF solo
    for _ in 0..1000 {
        let mut out = vec![0u8; 32];
        hkdf(&[0u8; 64], &[0u8; 16], b"redoubt-cipherbox:0.0.1", &mut out).unwrap();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let mut out = vec![0u8; 32];
        hkdf(&[0u8; 64], &[0u8; 16], b"redoubt-cipherbox:0.0.1", &mut out).unwrap();
    }
    let elapsed = start.elapsed();
    println!("hkdf(): {} ns/op", elapsed.as_nanos() / iterations as u128);

    // 3. derive_key completo (open + hkdf)
    for _ in 0..1000 {
        let _ = box_.derive_key().unwrap();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = box_.derive_key().unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "derive_key(): {} ns/op",
        elapsed.as_nanos() / iterations as u128
    );
}
