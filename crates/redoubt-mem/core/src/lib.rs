// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The routines behind `redoubt-mem`, and each one's backend.
//!
//! Everything here is public so that the forensics can reach what a caller does
//! not; a caller uses `redoubt-mem`.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod copy;
mod swap;
mod utf8;
mod zeroized;

pub mod backend;

pub use copy::{copy_nonoverlapping, copy_nonoverlapping_with_backend};
pub use swap::{swap, swap_nonoverlapping, swap_nonoverlapping_with_backend, swap_with_backend};
pub use utf8::{is_utf8, is_utf8_with_backend};
pub use zeroized::{is_zeroized, is_zeroized_with_backend};
