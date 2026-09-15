// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The choices this crate spells, for itself and for everything above it.

/// The Rust, or whatever the target has.
///
/// Here and not in each crate with a pair of backends: an AEAD is a cipher and
/// an authenticator standing together, and a test that wants the whole of it in
/// Rust hands both the same answer, which takes one type both of them accept.
///
/// What `Auto` resolves to is each crate's own business — a target has the
/// assembly for one primitive and not another. This says which was asked for,
/// not which was found.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Backend {
    /// The Rust, wherever it is asked for. Nothing outside a test asks: what
    /// ships takes the assembly where the target has it.
    Rust,
    /// The assembly on a target that has it, and the Rust on one that does
    /// not.
    #[default]
    Auto,
}
