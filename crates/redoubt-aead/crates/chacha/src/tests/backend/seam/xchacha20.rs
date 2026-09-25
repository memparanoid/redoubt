// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::array::TryFromSliceError;

use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_core::consts::chacha::{BLOCK_SIZE, KEY_SIZE, XNONCE_SIZE};
use redoubt_asm::Backend;

use crate::xchacha20::XChaCha20;

use crate::tests::support::{oracle, vectors};

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_rejects_counter_exhaustion_before_touching_data(#[case] backend: Backend) {
    let cipher = XChaCha20::new();

    for blocks in 1..=4u32 {
        let mut data = std::vec![0xa5; blocks as usize * BLOCK_SIZE + 1];
        let before = data.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            cipher.xor(
                backend,
                &[0x42; KEY_SIZE],
                &[0x17; XNONCE_SIZE],
                u32::MAX - blocks + 1,
                &mut data,
            );
        }));

        assert!(result.is_err(), "{blocks} blocks left");
        assert_eq!(data, before);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_ciphertext(#[case] backend: Backend) {
    let cipher = XChaCha20::new();

    for counter in 0..=1 {
        let mut data = vectors::DHOLE.to_vec();
        let expected = vectors::hex::<304>(vectors::XCIPHERTEXT[counter as usize]);

        cipher.xor(
            backend,
            &vectors::hex(vectors::XKEY),
            &vectors::hex(vectors::XNONCE),
            counter,
            &mut data,
        );
        assert_eq!(data, expected, "counter {counter}");

        cipher.xor(
            backend,
            &vectors::hex(vectors::XKEY),
            &vectors::hex(vectors::XNONCE),
            counter,
            &mut data,
        );
        assert_eq!(data, vectors::DHOLE);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_accepts_the_last_counter(#[case] backend: Backend) {
    let cipher = XChaCha20::new();
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; XNONCE_SIZE];

    for blocks in 1..=4u32 {
        let counter = u32::MAX - blocks + 1;

        for tail in 0..=BLOCK_SIZE {
            let length = (blocks as usize - 1) * BLOCK_SIZE + tail;
            let mut data = std::vec![0xa5; length];
            let expected = oracle::xxor(&key, &nonce, counter, &data);

            cipher.xor(backend, &key, &nonce, counter, &mut data);

            assert_eq!(data, expected, "counter {counter}, {length} bytes in");
        }
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_touches_only_the_named_bytes_at_every_alignment(
    #[case] backend: Backend,
) -> Result<(), TryFromSliceError> {
    let cipher = XChaCha20::new();

    for offset in 0..16 {
        let key_storage: [u8; KEY_SIZE + 16] = core::array::from_fn(|at| at as u8);
        let nonce_storage: [u8; XNONCE_SIZE + 16] = core::array::from_fn(|at| 0x80 + at as u8);
        let key = key_storage[offset..offset + KEY_SIZE].try_into()?;
        let nonce = nonce_storage[offset..offset + XNONCE_SIZE].try_into()?;

        for length in (0..=BLOCK_SIZE).chain(BLOCK_SIZE * 3..=BLOCK_SIZE * 4) {
            let plaintext = std::vec![0x5a; length];
            let expected = oracle::xxor(key, nonce, 7, &plaintext);
            let mut storage = std::vec![0xa5; offset + length + 16];
            storage[offset..offset + length].copy_from_slice(&plaintext);

            cipher.xor(
                backend,
                key,
                nonce,
                7,
                &mut storage[offset..offset + length],
            );

            assert_eq!(
                &storage[offset..offset + length],
                expected,
                "offset {offset}, length {length}"
            );
            assert!(storage[..offset].iter().all(|&byte| byte == 0xa5));
            assert!(storage[offset + length..].iter().all(|&byte| byte == 0xa5));
        }

        assert_eq!(key_storage, core::array::from_fn(|at| at as u8));
        assert_eq!(nonce_storage, core::array::from_fn(|at| 0x80 + at as u8));
    }

    Ok(())
}

proptest! {
    #[test]
    fn test_xor_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        nonce: [u8; XNONCE_SIZE],
        counter in 0..=u32::MAX - 32,
        plaintext in proptest::collection::vec(any::<u8>(), 0..2049),
    ) {
        let expected = oracle::xxor(&key, &nonce, counter, &plaintext);

        for backend in [Backend::Rust, Backend::Auto] {
            let mut data = plaintext.clone();
            XChaCha20::new().xor(backend, &key, &nonce, counter, &mut data);

            prop_assert_eq!(&data, &expected, "{:?}", backend);
        }
    }
}
