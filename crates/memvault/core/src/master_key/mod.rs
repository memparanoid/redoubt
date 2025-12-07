// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Master key storage

use membuffer::BufferError as MemBufferError;

use crate::BufferError;

mod buffer;
mod storage;

pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), MemBufferError>) -> Result<(), BufferError> {
    storage::open(f)
}
