// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Storage backend implementations

#[cfg(not(feature = "no_std"))]
mod std;

#[cfg(feature = "no_std")]
mod portable;

pub fn open<F, R>(f: F) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    #[cfg(not(feature = "no_std"))]
    {
        std::open(f)
    }
    #[cfg(feature = "no_std")]
    {
        portable::open(f)
    }
}

pub fn open_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut [u8]) -> R,
{
    #[cfg(not(feature = "no_std"))]
    {
        std::open_mut(f)
    }
    #[cfg(feature = "no_std")]
    {
        portable::open_mut(f)
    }
}
