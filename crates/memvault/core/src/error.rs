// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault error types

use membuffer::BufferError as MemBufferError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BufferError {
    #[error(transparent)]
    Buffer(#[from] MemBufferError),
    #[error("buffer mutex poisoned")]
    Poisoned,
}
