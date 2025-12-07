// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Storage backend implementations

use membuffer::BufferError;

#[cfg(not(feature = "no_std"))]
mod std;

#[cfg(feature = "no_std")]
mod portable;

pub fn open(
    f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
) -> Result<(), BufferError> {
    #[cfg(not(feature = "no_std"))]
    {
        std::open(f)
    }
    #[cfg(feature = "no_std")]
    {
        portable::open(f)
    }
}
