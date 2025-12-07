// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::master_key::buffer::MASTER_KEY_LEN;
use crate::master_key::storage::std::open;
use crate::tests::run::run_test_as_subprocess;

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
fn test_concurrent_access() {
    let exit_code =
        run_test_as_subprocess("tests::master_key::storage::std::subprocess_concurrent_access");
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
