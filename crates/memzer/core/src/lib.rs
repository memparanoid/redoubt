// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod drop_sentinel;
mod secret;
mod traits;
mod zeroizing_mut_guard;

pub mod assert;
pub mod collections;
pub mod primitives;
pub use drop_sentinel::DropSentinel;
pub use secret::Secret;
pub use traits::{AssertZeroizeOnDrop, MutGuarded, Zeroizable, ZeroizationProbe};
pub use zeroizing_mut_guard::ZeroizingMutGuard;

#[cfg(any(test, feature = "memcode"))]
mod mem_encode_buf;

#[cfg(any(test, feature = "memcode"))]
pub use mem_encode_buf::MemEncodeBuf;
