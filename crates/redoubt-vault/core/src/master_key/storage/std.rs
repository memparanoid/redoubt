// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Standard library storage implementation

use std::sync::{Mutex, OnceLock};

use redoubt_buffer::{Buffer, BufferError};

use super::super::buffer::create_initialized_buffer;

static BUFFER: OnceLock<Mutex<Box<dyn Buffer>>> = OnceLock::new();

pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>) -> Result<(), BufferError> {
    let mutex = BUFFER.get_or_init(|| Mutex::new(create_initialized_buffer()));
    let mut guard = mutex.lock().map_err(|_| BufferError::MutexPoisoned)?;
    guard.open(f)
}

/// Resets the master key storage (forensics only)
///
/// # Safety
///
/// This function is only available with the `internal-forensics` feature.
/// It reinitializes the master key buffer, discarding the previous key material.
/// This should only be used for memory leak detection in controlled testing environments.
///
/// # Panics
///
/// Panics if the buffer has not been initialized yet or if the mutex is poisoned.
#[cfg(all(feature = "internal-forensics", not(feature = "no_std")))]
pub fn reset() {
    let mutex = BUFFER
        .get()
        .expect("BUFFER must be initialized before reset");
    let mut guard = mutex.lock().expect("Mutex must not be poisoned");
    *guard = create_initialized_buffer();
}
