// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The one choice this crate spells.

/// The Rust, or whatever the target has.
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
