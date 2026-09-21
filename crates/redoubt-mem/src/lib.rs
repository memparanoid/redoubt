// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Moving a secret from one place to another without leaving it in a register.
//!
//! # What is wrong with the obvious way
//!
//! ```text
//! core::ptr::copy_nonoverlapping(src, dst, n)     // n known only at run time
//! ```
//!
//! A length the compiler cannot see cannot be unrolled, so this becomes a jump
//! into the C library's `memcpy`. What that does with the bytes is the C
//! library's business, and glibc's business — on a machine with AVX-512 — is
//! to move them through `zmm16` and `zmm17`.
//!
//! Those two are the problem. `zmm16-31` are outside every form of `vzeroall`,
//! and compiled Rust never writes to them, so nothing in the rest of the
//! program will ever overwrite what was left there. It is not a race that is
//! usually won. It is a resting place, and the secret stays in it until the
//! process dies.
//!
//! Registers are not out of reach of memory either. A signal writes the whole
//! register file into the signal frame, **on the process's own stack**; a core
//! dump writes it to disk; a context switch writes it into the kernel. A dirty
//! `zmm16` is one signal away from being bytes somebody can read.
//!
//! # What is here instead
//!
//! [`copy_nonoverlapping`] takes the same arguments in the same order, and
//! calls an assembly routine whose temporaries are known and are erased before
//! it returns. It is a call across an ABI boundary, which is also what stops
//! the optimiser from replacing the body with a copy of its own.
//!
//! The promise is narrow and worth reading as written: on a normal return,
//! every architectural temporary **that routine** put copied bytes into is
//! zero. Not the source, not the destination, not the registers somebody else
//! dirtied, and nothing at all if a fault stops the epilogue from being
//! reached.
//!
//! It is not a replacement for `memcpy` and it does not change what Rust emits
//! for an ordinary move or assignment. It is a thing a caller reaches for
//! where it wants this property, and nowhere else.
//!
//! # Where there is no assembly
//!
//! Anywhere but Unix on `x86_64` or `aarch64`, this is
//! [`core::ptr::copy_nonoverlapping`] and **there is no erasure**. The call
//! compiles and the guarantee does not travel with it.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod copy;
mod swap;

pub use copy::copy_nonoverlapping;
pub use swap::{swap, swap_nonoverlapping};
