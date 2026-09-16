// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L, the AES round function used as a permutation.
//!
//! One key, one nonce, one message. The state is eight blocks of a hundred and
//! twenty-eight bits, and it lives in the vector registers for the length of a
//! call.
//!
//! There is no portable implementation to fall back to. AEGIS *is* the AES
//! round function, and one written in ordinary Rust would be a different
//! algorithm wearing the same name: slower by two orders of magnitude, and
//! leaking through the table lookup that stands in for the instruction.
//!
//! The build script assembles for every target whose ABI fits and asks nothing
//! about the machine that will run the result. One without AES stops at the
//! first instruction rather than answering wrong, so that question is asked at
//! runtime, where this AEAD is chosen over another.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod aegis128l;
mod asm;

pub use aegis128l::Aegis128L;

/// Whether the build script found assembly for this target.
///
/// False means the symbols [`Aegis128L`] calls were never assembled, and
/// anything that links this crate will not find them. It says nothing about
/// whether the machine running the result has the AES instructions.
pub const HAS_ASM: bool = cfg!(aegis_asm);
