// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::ProtectedBufferError;

pub trait Buffer {
    fn open<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&[u8]) -> Result<(), ProtectedBufferError>;

    fn open_mut<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&mut [u8]) -> Result<(), ProtectedBufferError>;
}
