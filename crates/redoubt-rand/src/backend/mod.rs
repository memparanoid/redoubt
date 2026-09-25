// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The fill, once from the `getrandom` crate and once by hand.
//!
//! `rand_asm` is set by the build script for a target it compiled assembly for,
//! and it is named nowhere but the alias below: `Auto` is whatever was chosen
//! for this target.

pub(crate) mod rust;

#[cfg(rand_asm)]
pub(crate) mod asm;

#[cfg(rand_asm)]
use asm as chosen;

#[cfg(not(rand_asm))]
use rust as chosen;

use redoubt_asm::Backend;

use crate::error::EntropyError;

/// Whether this target was built with assembly.
#[cfg(test)]
pub(crate) const HAS_ASM: bool = cfg!(rand_asm);

pub(crate) fn fill(backend: Backend, dest: &mut [u8]) -> Result<(), EntropyError> {
    match backend {
        Backend::Rust => rust::fill(dest),
        Backend::Auto => chosen::fill(dest),
    }
}
