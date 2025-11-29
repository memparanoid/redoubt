// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! High-performance secure codec with memory zeroization.

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "benchmark"))]
mod bench;

mod buffer;
pub mod collections;
mod error;
mod primitives;
mod traits;
mod wrappers;

pub use error::{DecodeError, EncodeError, OverflowError};
pub use traits::{BytesRequired, CodecBuffer, Decode, DecodeBuffer, Encode};
