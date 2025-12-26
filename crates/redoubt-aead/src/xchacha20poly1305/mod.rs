// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod aead;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod asm;
mod chacha20;
mod consts;
mod poly1305;
mod types;

pub(crate) use aead::XChacha20Poly1305;
