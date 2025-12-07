// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::master_key::buffer::MASTER_KEY_LEN;
use crate::master_key::storage::std::open;

fn run_test_as_subprocess(test_name: &str) -> Option<i32> {
    let exe = std::env::current_exe().expect("Failed to get current exe");
    let status = std::process::Command::new(exe)
        .args(["--exact", test_name, "--ignored", "--test-threads=1", "--nocapture"])
        .status()
        .expect("Failed to run subprocess");

    status.code()
}

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
#[ignore]
fn subprocess_concurrent_access() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    const NUM_THREADS: usize = 256;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let reference_key = Arc::new(Mutex::new(None::<[u8; MASTER_KEY_LEN]>));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let reference_key = Arc::clone(&reference_key);

            thread::spawn(move || {
                barrier.wait();

                let mut thread_key = [0u8; MASTER_KEY_LEN];
                open(&mut |bytes| {
                    thread_key.copy_from_slice(bytes);
                    Ok(())
                })
                .expect("Failed to open std buffer");

                let mut ref_guard = reference_key.lock().unwrap();
                match *ref_guard {
                    None => *ref_guard = Some(thread_key),
                    Some(ref expected) => {
                        assert_eq!(&thread_key, expected, "thread got different key");
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_concurrent_access() {
    let exit_code =
        run_test_as_subprocess("tests::master_key::std::subprocess_concurrent_access");
    assert_eq!(exit_code, Some(0), "subprocess test failed");
}
