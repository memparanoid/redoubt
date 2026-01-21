// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for global storage with portable (no_std) strategy

#[cfg(test)]
mod storage_portable {
    use std::sync::atomic::{AtomicU64, Ordering};

    use redoubt_codec::RedoubtCodec;
    use redoubt_secret::RedoubtSecret;
    use redoubt_vault_core::CipherBoxError;
    use redoubt_vault_derive::cipherbox;
    use redoubt_zero::{RedoubtZero, StaticFastZeroizable};

    #[cipherbox(ZeroizeTestBox, global = true, storage = "portable")]
    #[derive(Default, RedoubtCodec, RedoubtZero)]
    struct ZeroizeTestData {
        secret: RedoubtSecret<u64>,
    }

    #[test]
    fn test_fast_zeroize_then_open_returns_zeroized_error() {
        // First open should succeed
        ZEROIZE_TEST_BOX::open(|_| Ok::<(), CipherBoxError>(()))
            .expect("open should succeed before zeroize");

        // Zeroize the global instance
        ZEROIZE_TEST_BOX::fast_zeroize();

        // After zeroize, open should return Zeroized error
        let result = ZEROIZE_TEST_BOX::open(|_| Ok::<(), CipherBoxError>(()));
        assert!(matches!(result, Err(CipherBoxError::Zeroized)));

        let result = ZEROIZE_TEST_BOX::open_mut(|_| Ok::<(), CipherBoxError>(()));
        assert!(matches!(result, Err(CipherBoxError::Zeroized)));

        let result = ZEROIZE_TEST_BOX::open_secret(|_| Ok::<(), CipherBoxError>(()));
        assert!(matches!(result, Err(CipherBoxError::Zeroized)));

        let result = ZEROIZE_TEST_BOX::open_secret_mut(|_| Ok::<(), CipherBoxError>(()));
        assert!(matches!(result, Err(CipherBoxError::Zeroized)));

        let result = ZEROIZE_TEST_BOX::leak_secret();
        assert!(matches!(result, Err(CipherBoxError::Zeroized)));
    }

    #[cipherbox(TestBox, global = true, storage = "portable")]
    #[derive(Default, RedoubtCodec, RedoubtZero)]
    struct TestData {
        counter: RedoubtSecret<u64>,
    }

    static ACCESS_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn test_concurrent_global_access() {
        const NUM_THREADS: u64 = 300;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                std::thread::spawn(|| {
                    // Read and increment access counter atomically
                    let value = ACCESS_COUNTER.fetch_add(1, Ordering::SeqCst);

                    // Sum using open_mut (whole struct access)
                    TEST_BOX::open_mut(|data| {
                        let current = *data.counter.as_ref();
                        data.counter.replace(&mut (current + value));
                        Ok::<(), CipherBoxError>(())
                    })
                    .expect("open_mut should succeed");

                    // Sum using open_counter_mut (field-specific access)
                    TEST_BOX::open_counter_mut(|counter| {
                        let current = *counter.as_ref();
                        counter.replace(&mut (current + value));
                        Ok::<(), CipherBoxError>(())
                    })
                    .expect("open_counter_mut should succeed");
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // Verify final value
        // Each thread adds its access_counter value twice:
        //   1. Via open_mut on the whole struct
        //   2. Via open_counter_mut on the specific field
        // Sum of 0..299 = (300 * 299) / 2 = 44850
        // Multiplied by 2 (two additions per thread) = 89700
        let expected = ((NUM_THREADS * (NUM_THREADS - 1)) / 2) * 2;

        TEST_BOX::open_counter(|counter| {
            assert_eq!(
                *counter.as_ref(),
                expected,
                "Final counter value should match expected sum"
            );
            Ok::<(), CipherBoxError>(())
        })
        .expect("final verification should succeed");
    }
}
