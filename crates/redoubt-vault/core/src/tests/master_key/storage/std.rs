// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_buffer::BufferError;

use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::storage::std::open;
use crate::tests::utils::run_test_as_subprocess;

#[test]
fn test_open_returns_correct_length() {
    open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        Ok(())
    })
    .expect("Failed to open std buffer");
}

#[test]
fn test_open_returns_same_bytes_on_subsequent_calls() {
    let mut first_bytes = [0u8; MASTER_KEY_LEN];

    open(&mut |bytes| {
        first_bytes.copy_from_slice(bytes);
        Ok(())
    })
    .expect("Failed to open std buffer");

    open(&mut |bytes| {
        assert_eq!(bytes, &first_bytes);
        Ok(())
    })
    .expect("Failed to open std buffer");
}

#[test]
fn test_open_propagates_callback_error() {
    #[derive(Debug)]
    struct CustomCallbackError {}

    let result = open(&mut |_| Err(BufferError::callback_error(CustomCallbackError {})));
    assert!(result.is_err());
}

#[test]
fn test_concurrent_access() {
    let exit_code =
        run_test_as_subprocess("tests::master_key::storage::std::subprocess_concurrent_access");
    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

#[test]
fn test_mutex_poisoned() {
    let exit_code =
        run_test_as_subprocess("tests::master_key::storage::std::subprocess_test_mutex_poisoned");
    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

// ==============================
// ===== Subprocess tests =======
// ==============================

#[test]
#[ignore]
fn subprocess_concurrent_access() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    const NUM_THREADS: usize = 256;

    let keys = Arc::new(Mutex::new(Vec::<[u8; MASTER_KEY_LEN]>::new()));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let keys_clone = keys.clone();

            thread::spawn(move || {
                open(&mut |bytes| {
                    let mut guard = keys_clone.lock().expect("Failed to lock mutex");
                    let master_key: [u8; MASTER_KEY_LEN] = bytes.try_into().expect("Wrong length");
                    guard.push(master_key);

                    Ok(())
                })
                .expect("Failed to open std buffer");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let guard = keys.lock().expect("Failed to lock mutex");
    assert!(guard.iter().all(|x| *x == guard[0]));
}

#[test]
#[ignore]
fn subprocess_test_mutex_poisoned() {
    use std::panic;

    // First call: poison the Mutex by panicking inside the closure
    let result = panic::catch_unwind(|| {
        open(&mut |_| {
            panic!("Intentional panic to poison mutex");
        })
    });

    assert!(result.is_err(), "Expected panic");

    // Second call: should return MutexPoisoned error
    let result = open(&mut |_| Ok(()));

    match result {
        Err(BufferError::MutexPoisoned) => {
            // Success: we got the expected error
        }
        other => panic!("Expected MutexPoisoned error, got: {:?}", other),
    }
}
