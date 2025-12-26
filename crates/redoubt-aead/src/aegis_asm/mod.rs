// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L assembly implementations

#[cfg(all(test, is_aegis_asm_eligible))]
mod tests;

pub mod aead;
pub mod consts;

pub use aead::Aegis128L;
