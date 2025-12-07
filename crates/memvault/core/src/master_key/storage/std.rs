// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Standard library storage implementation

use std::sync::{Mutex, OnceLock};

use membuffer::{Buffer, BufferError as MemBufferError};

use crate::BufferError;

use super::super::buffer::create_initialized_buffer;

static BUFFER: OnceLock<Mutex<Box<dyn Buffer>>> = OnceLock::new();

pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), MemBufferError>) -> Result<(), BufferError> {
    let mut guard = BUFFER
        .get_or_init(|| Mutex::new(create_initialized_buffer()))
        .lock()
        .map_err(|_| BufferError::Poisoned)?;

    guard.open(f)?;

    Ok(())
}
