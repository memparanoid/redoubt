// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Authenticated encryption, with the algorithm chosen for the machine.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod aead;
mod enums;
mod errors;
mod feature_detector;
mod utils;

pub use aead::{Aead, AeadVariants};
pub use enums::AeadAlgorithm;
