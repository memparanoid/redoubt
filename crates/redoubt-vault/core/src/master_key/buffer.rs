// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Buffer creation logic
use alloc::boxed::Box;

use redoubt_buffer::{Buffer, BufferError, PortableBuffer};
use redoubt_rand::fill_with_random_bytes;

#[cfg(unix)]
use redoubt_buffer::PageBuffer;

use super::consts::MASTER_KEY_LEN;

#[cfg(not(unix))]
pub fn create_buffer() -> Box<dyn Buffer> {
    Box::new(PortableBuffer::create(MASTER_KEY_LEN))
}

#[cfg(unix)]
pub fn create_buffer() -> Box<dyn Buffer> {
    // SECURITY: the key's page is mlocked, kept at PROT_NONE between uses, and
    // excluded from core dumps with madvise(MADV_DONTDUMP). Everything that
    // guards it is on the mapping itself, so it holds whatever the process
    // around it does.
    match PageBuffer::new(MASTER_KEY_LEN) {
        Ok(buffer) => Box::new(buffer),
        // Silent: the key goes to the heap, with no mlock, mprotect or
        // madvise, and nothing tells the caller.
        Err(_) => Box::new(PortableBuffer::create(MASTER_KEY_LEN)),
    }
}

pub fn create_initialized_buffer() -> Box<dyn Buffer> {
    let mut buffer = create_buffer();

    buffer
        .open_mut(&mut |bytes| {
            fill_with_random_bytes(bytes).map_err(BufferError::callback_error)?;
            Ok(())
        })
        .expect("CRITICAL: Key generation failed");

    buffer
}
