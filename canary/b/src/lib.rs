// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! `test-a`'s generic at `Wide`, down the path that succeeds and no other.
//!
//! The monomorphization is compiled into this crate, and the regions it carries
//! belong to `test-a`'s source. Its error paths are reached by nothing here and
//! by nothing in `test-a`, which instantiates at `Narrow` only.

#![no_std]

#[cfg(test)]
mod tests;

use test_a::{Refused, Wide, twice_halved};

/// A quarter of four, at the instantiation `test-a` never makes.
///
/// # Errors
///
/// What `test-a` answers, which for this argument is never an error.
pub fn quarter_of_four() -> Result<u64, Refused> {
    twice_halved(&Wide(4))
}
