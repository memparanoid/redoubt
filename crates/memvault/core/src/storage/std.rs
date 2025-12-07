// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Standard library storage implementation

pub fn open<F, R>(_f: F) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    todo!()
}

pub fn open_mut<F, R>(_f: F) -> R
where
    F: FnOnce(&mut [u8]) -> R,
{
    todo!()
}
