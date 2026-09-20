// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Authenticated encryption, with the algorithm chosen for the machine.
//!
//! # `aes_asm` says the symbols exist, not that they run
//!
//! The flag is set for the targets AEGIS has assembly for, so what it answers
//! is a question about the build: whether there is anything to link. Whether
//! the machine running the result has the AES instructions is a different
//! question and no `cfg` can reach it — one binary runs on a CPU that has them
//! and on one that does not.
//!
//! So the check the feature detector makes at run time is not an optimisation
//! over gating, and no amount of gating replaces it: gating only spreads the
//! build's question through every caller, and the caller would still have to
//! ask the other one.
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

pub use aead::{Aead, AeadAlgorithms, AeadVariants};
pub use enums::AeadAlgorithm;
pub use errors::AeadError;

#[cfg(any(test, feature = "test-utils"))]
pub use enums::AeadBehaviour;
/// Support module including test utilities.
#[cfg(any(test, feature = "test-utils"))]
pub mod support;
