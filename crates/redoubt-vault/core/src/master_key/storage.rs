// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::boxed::Box;

use quiesce::Mutex;
use redoubt_buffer::{Buffer, BufferError};

use super::buffer::create_initialized_buffer;

static BUFFER: Mutex<Option<Box<dyn Buffer>>> = Mutex::new(None);

/// Hands the master key to `f`, making it on the first call; callers that
/// arrive while it is being made wait for it instead of making another.
pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>) -> Result<(), BufferError> {
    BUFFER
        .lock()
        .get_or_insert_with(create_initialized_buffer)
        .open(f)
}

/// Replaces the master key with a new one, for the memory analyses that need
/// a key they have not seen yet.
#[cfg(feature = "internal-forensics")]
pub fn reset() {
    *BUFFER.lock() = Some(create_initialized_buffer());
}
