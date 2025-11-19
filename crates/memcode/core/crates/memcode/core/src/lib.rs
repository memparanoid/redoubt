// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod error;
mod guards;
mod mem_encode_buf;
mod primitives;
mod support;
mod traits;

pub use guards::BytesGuard;
pub mod collections;
pub use error::{MemDecodeError, MemEncodeBufError, MemEncodeError, OverflowError};
pub use mem_encode_buf::MemEncodeBuf;
pub use traits::{
    CollectionDecode, CollectionEncode, DecodeIterator, EncodeIterator, MemBytesRequired,
    MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements, Zeroizable,
};

#[cfg(feature = "test_utils")]
pub use support::test_utils::memcode_test_breaker::{
    MemCodeTestBreaker, MemCodeTestBreakerBehaviour,
};
#[cfg(feature = "test_utils")]
pub use support::test_utils::utils::tamper_encoded_bytes_for_tests;
