// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::BufferError;

/// Trait for buffer types that provide temporary access to their contents.
pub trait Buffer: Send + Sync + core::fmt::Debug {
    /// Opens the buffer for read-only access, executing the provided closure.
    fn open(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError>;

    /// Opens the buffer for mutable access, executing the provided closure.
    fn open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError>;

    /// Returns the length of the buffer in bytes.
    fn len(&self) -> usize;

    /// Returns true if the buffer has zero length.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
