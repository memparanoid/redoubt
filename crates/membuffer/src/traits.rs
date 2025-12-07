// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::ProtectedBufferError;

pub trait Buffer: Send + Sync {
    fn open(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> Result<(), ProtectedBufferError>,
    ) -> Result<(), ProtectedBufferError>;

    fn open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), ProtectedBufferError>,
    ) -> Result<(), ProtectedBufferError>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
