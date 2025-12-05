// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! High-performance secure codec with memory zeroization.

#[cfg(test)]
mod tests;

mod codec_buffer;
mod decode_buffer;
mod error;
mod primitives;
mod support;
mod traits;
mod wrappers;

pub mod collections;

pub use codec_buffer::CodecBuffer;
pub use error::{DecodeError, EncodeError, OverflowError};
pub use traits::{BytesRequired, Decode, DecodeBuffer, DecodeZeroize, Encode, EncodeZeroize};

#[cfg(feature = "test_utils")]
pub use support::test_utils;
