// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::array::TryFromSliceError;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::vec::Vec;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_core::consts::chacha::{
    BERNSTEIN_NONCE_SIZE, BLOCK_SIZE, KEY_SIZE, NONCE_SIZE,
};
use redoubt_asm::Backend;

use crate::chacha20::ChaCha20;

use crate::tests::support::vectors::{VECTORS, Vector};
use crate::tests::support::{oracle, vectors};

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_rejects_counter_exhaustion_before_touching_data(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);

    for blocks in 1..=4u32 {
        let mut data = std::vec![0xa5; blocks as usize * BLOCK_SIZE + 1];
        let before = data.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            cipher.xor(
                &[0x42; KEY_SIZE],
                &[0x17; NONCE_SIZE],
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
    let cipher = ChaCha20::with_backend(backend);

    for Vector {
        from,
        key,
        nonce,
        counter,
        plaintext,
        ciphertext,
    } in VECTORS
    {
        let mut data: Vec<u8> = plaintext.to_vec();
        cipher.xor(key, nonce, *counter, &mut data);

        assert_eq!(&data, ciphertext, "{from}");
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_plaintext_when_it_is_run_twice(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; NONCE_SIZE];

    // Over a block boundary and past it, so the counter has to move and the
    // last block has to be a partial one.
    let plaintext: Vec<u8> = (0..BLOCK_SIZE * 2 + 7).map(|at| at as u8).collect();
    let mut data = plaintext.clone();

    cipher.xor(&key, &nonce, 0, &mut data);
    assert_ne!(data, plaintext);

    cipher.xor(&key, &nonce, 0, &mut data);
    assert_eq!(data, plaintext);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_advances_one_counter_per_block(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; NONCE_SIZE];

    for length in [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1025] {
        let plaintext: Vec<u8> = (0..length).map(|at| at as u8).collect();
        let mut whole = plaintext.clone();
        let mut split = plaintext;

        cipher.xor(&key, &nonce, 7, &mut whole);

        for (at, chunk) in split.chunks_mut(BLOCK_SIZE).enumerate() {
            cipher.xor(&key, &nonce, 7 + at as u32, chunk);
        }

        assert_eq!(whole, split, "{length} bytes in");
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_accepts_the_last_counter(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; NONCE_SIZE];

    for blocks in 1..=4u32 {
        let counter = u32::MAX - blocks + 1;

        for tail in 0..=BLOCK_SIZE {
            let length = (blocks as usize - 1) * BLOCK_SIZE + tail;
            let mut whole = std::vec![0; length];
            let mut split = whole.clone();

            cipher.xor(&key, &nonce, counter, &mut whole);

            for (at, chunk) in split.chunks_mut(BLOCK_SIZE).enumerate() {
                cipher.xor(&key, &nonce, counter + at as u32, chunk);
            }

            assert_eq!(whole, split, "counter {counter}, {length} bytes in");
        }
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_touches_only_the_named_bytes_at_every_alignment(
    #[case] backend: Backend,
) -> Result<(), TryFromSliceError> {
    let cipher = ChaCha20::with_backend(backend);

    for offset in 0..16 {
        let key_storage = [0x42; KEY_SIZE + 16];
        let nonce_storage = [0x17; NONCE_SIZE + 16];
        let key = key_storage[offset..offset + KEY_SIZE].try_into()?;
        let nonce: &[u8; NONCE_SIZE] = nonce_storage[offset..offset + NONCE_SIZE].try_into()?;

        // Every possible tail, including empty and full blocks, after more
        // than two full blocks as well as at the start of a message.
        for length in (0..=BLOCK_SIZE).chain(BLOCK_SIZE * 3..=BLOCK_SIZE * 4) {
            let plaintext = std::vec![0x5a; length];
            let expected = oracle::xor(key, nonce, 7, &plaintext);
            let mut storage = std::vec![0xa5; offset + length + 16];
            storage[offset..offset + length].copy_from_slice(&plaintext);

            cipher.xor(key, nonce, 7, &mut storage[offset..offset + length]);

            assert_eq!(
                &storage[offset..offset + length],
                expected,
                "offset {offset}, length {length}"
            );
            assert!(storage[..offset].iter().all(|&byte| byte == 0xa5));
            assert!(storage[offset + length..].iter().all(|&byte| byte == 0xa5));
        }

        assert_eq!(key_storage, [0x42; KEY_SIZE + 16]);
        assert_eq!(nonce_storage, [0x17; NONCE_SIZE + 16]);
    }

    Ok(())
}

proptest! {
    #[test]
    fn test_xor_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
        counter in 0..=u32::MAX - 32,
        plaintext in proptest::collection::vec(any::<u8>(), 0..2049),
    ) {
        let expected = oracle::xor(&key, &nonce, u64::from(counter), &plaintext);

        for backend in [Backend::Rust, Backend::Auto] {
            let mut data = plaintext.clone();
            ChaCha20::with_backend(backend).xor(&key, &nonce, counter, &mut data);

            prop_assert_eq!(&data, &expected, "{:?}", backend);
        }
    }
}

// === === === === === === === === === ===
// xor_bernstein
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_bernstein_rejects_counter_exhaustion_before_touching_data(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);

    for blocks in 1..=4u64 {
        let mut data = std::vec![0xa5; blocks as usize * BLOCK_SIZE + 1];
        let before = data.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            cipher.xor_bernstein(
                &[0x42; KEY_SIZE],
                &[0x17; BERNSTEIN_NONCE_SIZE],
                u64::MAX - blocks + 1,
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
fn test_xor_bernstein_returns_the_published_blocks(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let mut data = [0u8; BLOCK_SIZE];

    cipher.xor_bernstein(&[0; KEY_SIZE], &[0; BERNSTEIN_NONCE_SIZE], 0, &mut data);
    assert_eq!(data, vectors::hex::<BLOCK_SIZE>(vectors::ZERO_BLOCK));

    data.fill(0);
    let key = core::array::from_fn(|at| at as u8);
    let nonce = vectors::hex("0000004a00000000");

    cipher.xor_bernstein(&key, &nonce, 0x09000000_00000001, &mut data);
    assert_eq!(data, vectors::hex::<BLOCK_SIZE>(vectors::BLOCK));
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_bernstein_carries_without_changing_the_nonce(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x53; KEY_SIZE];
    let nonce = [0xa7; BERNSTEIN_NONCE_SIZE];

    for counter in [
        0,
        u64::from(u32::MAX) - 1,
        0x08ffffff_ffffffff,
        u64::MAX - 4,
    ] {
        let plaintext = [0x37; BLOCK_SIZE * 4 + 1];
        let expected = oracle::xor(&key, &nonce, counter, &plaintext);
        let mut data = plaintext;

        cipher.xor_bernstein(&key, &nonce, counter, &mut data);
        assert_eq!(data.as_slice(), expected, "counter {counter}");

        cipher.xor_bernstein(&key, &nonce, counter, &mut data);
        assert_eq!(data, plaintext);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_bernstein_accepts_the_last_counter(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; BERNSTEIN_NONCE_SIZE];

    for length in 0..=BLOCK_SIZE {
        let mut data = std::vec![0xa5; length];
        let expected = oracle::xor(&key, &nonce, u64::MAX, &data);

        cipher.xor_bernstein(&key, &nonce, u64::MAX, &mut data);
        assert_eq!(data, expected, "{length} bytes in");
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_bernstein_touches_only_the_named_bytes_at_every_alignment(
    #[case] backend: Backend,
) -> Result<(), TryFromSliceError> {
    let cipher = ChaCha20::with_backend(backend);

    for offset in 0..16 {
        let key_storage = [0x42; KEY_SIZE + 16];
        let nonce_storage = [0x17; BERNSTEIN_NONCE_SIZE + 16];
        let key = key_storage[offset..offset + KEY_SIZE].try_into()?;
        let nonce: &[u8; BERNSTEIN_NONCE_SIZE] =
            nonce_storage[offset..offset + BERNSTEIN_NONCE_SIZE].try_into()?;

        for length in (0..=BLOCK_SIZE).chain(BLOCK_SIZE * 3..=BLOCK_SIZE * 4) {
            let plaintext = std::vec![0x5a; length];
            let expected = oracle::xor(key, nonce, 7, &plaintext);
            let mut storage = std::vec![0xa5; offset + length + 16];
            storage[offset..offset + length].copy_from_slice(&plaintext);

            cipher.xor_bernstein(key, nonce, 7, &mut storage[offset..offset + length]);

            assert_eq!(
                &storage[offset..offset + length],
                expected,
                "offset {offset}, length {length}"
            );
            assert!(storage[..offset].iter().all(|&byte| byte == 0xa5));
            assert!(storage[offset + length..].iter().all(|&byte| byte == 0xa5));
        }

        assert_eq!(key_storage, [0x42; KEY_SIZE + 16]);
        assert_eq!(nonce_storage, [0x17; BERNSTEIN_NONCE_SIZE + 16]);
    }

    Ok(())
}

proptest! {
    #[test]
    fn test_xor_bernstein_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        nonce: [u8; BERNSTEIN_NONCE_SIZE],
        counter in 0..=u64::MAX - 32,
        plaintext in proptest::collection::vec(any::<u8>(), 0..2049),
    ) {
        let expected = oracle::xor(&key, &nonce, counter, &plaintext);

        for backend in [Backend::Rust, Backend::Auto] {
            let mut data = plaintext.clone();
            ChaCha20::with_backend(backend).xor_bernstein(&key, &nonce, counter, &mut data);

            prop_assert_eq!(&data, &expected, "{:?}", backend);
        }
    }
}

// === === === === === === === === === ===
// with_backend
// === === === === === === === === === ===

#[test]
fn test_with_backend_defaults_to_auto() {
    assert_eq!(ChaCha20::new(), ChaCha20::with_backend(Backend::Auto));
    assert_eq!(ChaCha20::default(), ChaCha20::new());
    assert_ne!(ChaCha20::with_backend(Backend::Rust), ChaCha20::new());
}
