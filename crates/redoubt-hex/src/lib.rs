// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bytes to hex and back, in a time that says nothing about the bytes, and
//! with none of them left in a register where there is assembly for the
//! target.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
mod tests;

mod backend;
mod decode;
mod encode;
mod error;

pub use decode::hex_to_bytes;
pub use encode::bytes_to_hex;
pub use error::HexError;
