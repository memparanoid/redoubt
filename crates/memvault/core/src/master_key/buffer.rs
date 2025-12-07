// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Buffer creation logic

extern crate alloc;

use alloc::boxed::Box;

use membuffer::{Buffer, BufferError, PortableBuffer};
use memrand::{EntropySource, SystemEntropySource};

#[cfg(all(unix, not(target_os = "wasi")))]
use membuffer::{ProtectedBuffer, ProtectionStrategy};

use super::consts::MASTER_KEY_LEN;

#[cfg(any(target_os = "wasi", not(unix)))]
pub fn create_buffer(_is_guarded: bool) -> Box<dyn Buffer> {
    Box::new(PortableBuffer::create(MASTER_KEY_LEN))
}

#[cfg(all(unix, not(target_os = "wasi")))]
pub fn create_buffer(is_guarded: bool) -> Box<dyn Buffer> {
    let strategy = if is_guarded {
        ProtectionStrategy::MemNonProtected
    } else {
        ProtectionStrategy::MemProtected
    };

    match ProtectedBuffer::try_create(strategy, MASTER_KEY_LEN) {
        Ok(buffer) => Box::new(buffer),
        Err(_) => Box::new(PortableBuffer::create(MASTER_KEY_LEN)),
    }
}

pub fn create_initialized_buffer() -> Box<dyn Buffer> {
    #[cfg(all(unix, not(target_os = "wasi")))]
    let is_guarded = memguard::is_guarded();
    #[cfg(any(target_os = "wasi", not(unix)))]
    let is_guarded = false;

    let mut buffer = create_buffer(is_guarded);

    buffer
        .open_mut(&mut |bytes| {
            SystemEntropySource {}
                .fill_bytes(bytes)
                .map_err(|e| BufferError::callback_error(e))?;
            Ok(())
        })
        .expect("CRITICAL: Entropy not available");

    buffer
}
