// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::boxed::Box;

use quiesce::Mutex;
use redoubt_buffer::{Buffer, BufferError};

use super::buffer::create_initialized_buffer;

static BUFFER: Mutex<Option<Box<dyn Buffer>>> = Mutex::new(None);

/// Hands the master key to `f`, making it on the first call; callers that
/// arrive while it is being made wait for it instead of making another. A key
/// that cannot be made is an error, and the next call tries again.
pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>) -> Result<(), BufferError> {
    let mut held = BUFFER.lock();

    let buffer = match held.as_mut() {
        Some(buffer) => buffer,
        None => held.insert(create_initialized_buffer()?),
    };

    buffer.open(f)
}
