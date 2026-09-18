// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Which implementation a primitive runs.
//!
//! Nothing sits below this crate and it has no dependency at all. What it holds
//! is one enum, and it is here rather than in each crate with a pair of
//! implementations because a construction is several primitives standing
//! together: a test that wants the whole of a chain in Rust hands the same
//! answer to every one of them, and that takes a type all of them accept.
//!
//! What it does not hold is whether a target *has* assembly. That is each
//! crate's own business — a machine has it for one primitive and not for the
//! next — and it is answered beside each crate's seam, from the `cfg` its own
//! build script sets.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
mod tests;

mod enums;

pub use enums::Backend;
