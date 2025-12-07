// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Standard library storage implementation

use membuffer::BufferError;

pub fn open(
    _f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
) -> Result<(), BufferError> {
    todo!()
}
