// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Type aliases for the widths this codec writes.

/// How many elements a collection holds, and how many bytes it takes, as its
/// header carries them.
///
/// Eight bytes on every target, where a `usize` is four on `wasm32` and eight
/// on `x86_64`. The header is read by whoever receives the payload, not by
/// whoever wrote it.
pub(crate) type Len = u64;
