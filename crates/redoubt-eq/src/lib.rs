// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Two runs of bytes compared in a time that says nothing about where they
//! differ, and with neither left in a register where there is assembly for the
//! target.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod backend;
mod eq;

pub use eq::constant_time_eq;
