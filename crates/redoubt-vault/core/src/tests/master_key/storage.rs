// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::error::Error;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use redoubt_buffer::BufferError;

use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::storage::open;
use crate::tests::utils::run_test_as_subprocess;

const DEADLINE: Duration = Duration::from_secs(10);

// ============================================================================
// open
// ============================================================================

#[test]
fn test_open_hands_the_whole_key() -> Result<(), Box<dyn Error>> {
    open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_open_hands_the_same_key_every_time() -> Result<(), Box<dyn Error>> {
    let mut first_bytes = [0u8; MASTER_KEY_LEN];

    open(&mut |bytes| {
        first_bytes.copy_from_slice(bytes);
        Ok(())
    })?;

    open(&mut |bytes| {
        assert_eq!(bytes, &first_bytes);
        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_open_propagates_callback_error() {
    #[derive(Debug, thiserror::Error)]
    #[error("a test callback refused")]
    struct CustomCallbackError {}

    let result = open(&mut |_| Err(BufferError::callback_error(CustomCallbackError {})));

    assert!(matches!(result, Err(BufferError::CallbackError(_))));
}

#[test]
fn test_open_hands_every_thread_the_same_key() {
    let exit_code =
        run_test_as_subprocess("tests::master_key::storage::subprocess_every_thread_the_same_key");

    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

#[test]
fn test_open_is_taken_again_after_a_callback_panicked() {
    let exit_code = run_test_as_subprocess(
        "tests::master_key::storage::subprocess_taken_again_after_a_callback_panicked",
    );

    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

// ==============================
// ===== Subprocess tests =======
// ==============================

#[test]
#[ignore]
fn subprocess_every_thread_the_same_key() -> Result<(), Box<dyn Error>> {
    use std::sync::{Arc, Mutex};

    const NUM_THREADS: usize = 256;
    const POISONED: &str = "the keys mutex was poisoned";

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct Refused(&'static str);

    let keys = Arc::new(Mutex::new(Vec::<[u8; MASTER_KEY_LEN]>::new()));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let keys_clone = keys.clone();

            thread::spawn(move || {
                open(&mut |bytes| {
                    let mut guard = keys_clone
                        .lock()
                        .map_err(|_| BufferError::callback_error(Refused(POISONED)))?;

                    let master_key: [u8; MASTER_KEY_LEN] = bytes.try_into().map_err(|_| {
                        BufferError::callback_error(Refused("the key is not that wide"))
                    })?;

                    guard.push(master_key);

                    Ok(())
                })
            })
        })
        .collect();

    for handle in handles {
        handle.join().map_err(|_| "a thread panicked")??;
    }

    let guard = keys.lock().map_err(|_| POISONED)?;

    assert_eq!(guard.len(), NUM_THREADS);
    assert!(guard.iter().all(|x| *x == guard[0]));

    Ok(())
}

#[test]
#[ignore]
fn subprocess_taken_again_after_a_callback_panicked() {
    let panicked = std::panic::catch_unwind(|| {
        open(&mut |_| {
            panic!("the callback panics while the storage is open");
        })
    });

    assert!(panicked.is_err(), "the callback did not panic");

    let (opened, opening) = mpsc::channel();

    thread::spawn(move || {
        let _ = opened.send(open(&mut |_| Ok(())).is_ok());
    });

    let answer = opening
        .recv_timeout(DEADLINE)
        .expect("the storage was not opened again after the panic");

    assert!(answer, "the storage refused to open after the panic");
}
