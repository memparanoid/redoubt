// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! High-performance secure codec with memory zeroization.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod blankets;
mod codec_buffer;
mod decode_buffer;
mod error;
mod primitives;
mod traits;
mod zeroizing;

pub mod collections;

#[cfg(any(test, feature = "test-utils"))]
pub mod support;

pub use codec_buffer::RedoubtCodecBuffer;
pub use error::{DecodeError, EncodeError, OverflowError};
pub use traits::{BytesRequired, Decode, DecodeBuffer, DecodeZeroize, Encode, EncodeZeroize};
