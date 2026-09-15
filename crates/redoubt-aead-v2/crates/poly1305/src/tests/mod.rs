// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(poly1305_asm)]
mod asm;

#[cfg(poly1305_asm)]
mod probe;

mod poly1305;
mod support;
