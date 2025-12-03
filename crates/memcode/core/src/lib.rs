// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memcode-core
//!
//! Allocation-free, zeroizing serialization primitives for protecting sensitive data during encoding and decoding.
//!
//! `memcode-core` provides a systematic framework for encoding and decoding Rust types **without re-allocations**
//! and with **guaranteed zeroization** of source data and consumed buffers.
//!
//! ## Core Problem
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//! ## Design Principles
//!
//! 1. **Zero re-allocations**: Calculate exact size upfront via [`MemBytesRequired`], pre-allocate once
//! 2. **Move semantics**: `drain_*` methods consume source data and zeroize it
//! 3. **Systematic zeroization**: All buffers cleaned on success **and** error paths
//! 4. **Composability**: Traits work with nested types, collections, custom structs
//!
//! ## Quick Start
//!
//! ### Basic Encoding/Decoding
//!
//! ```rust
//! use memcode_core::{MemEncodeBuf, MemEncode, MemDecode, MemBytesRequired, FastZeroizable};
//!
//! let mut value = vec![1u8, 2, 3, 4, 5];
//!
//! // Calculate size upfront (no allocation yet)
//! let size = value.mem_bytes_required().expect("Failed to calculate size");
//!
//! // Pre-allocate buffer with exact size
//! let mut buf = MemEncodeBuf::new(size);
//!
//! // Encode (moves data, zeroizes source)
//! value.drain_into(&mut buf).expect("Failed to encode");
//!
//! // Source is now zeroized
//! assert!(value.iter().all(|&b| b == 0));
//!
//! // Decode (zeroizes consumed bytes)
//! let mut decoded = Vec::<u8>::new();
//! decoded.drain_from(buf.as_mut_slice()).expect("Failed to decode");
//!
//! assert_eq!(decoded, vec![1, 2, 3, 4, 5]);
//! ```
//!
//! ### Using with Custom Structs (via derive macro)
//!
//! ```rust,ignore
//! use memcode::{MemCodec, MemEncodable, MemDecodable};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize, MemCodec)]
//! #[zeroize(drop)]
//! struct Data {
//!     field_a: Vec<u8>,
//!     field_b: [u8; 32],
//!     field_c: u64,
//! }
//!
//! let mut data = Data {
//!     field_a: vec![1, 2, 3],
//!     field_b: [0u8; 32],
//!     field_c: 42,
//! };
//!
//! // Encode (zeroizes source)
//! let size = data.mem_bytes_required()?;
//! let mut buf = MemEncodeBuf::new(size);
//! data.drain_into(&mut buf)?;
//!
//! // data is now zeroized
//! ```
//!
//! ## Core Traits
//!
//! ### Encoding Traits
//!
//! - **[`MemBytesRequired`]**: Calculate exact serialization size before allocating
//! - **[`MemEncode`]**: Encode data into buffer with `drain_into()` (consumes + zeroizes source)
//! - **[`MemNumElements`]**: Report number of fields (for collections header)
//! - **[`MemEncodable`]**: Marker trait combining all encoding requirements
//!
//! ### Decoding Traits
//!
//! - **[`MemDecode`]**: Decode data from bytes with `drain_from()` (zeroizes consumed bytes)
//! - **[`MemDecodable`]**: Marker for decodable types
//!
//! ### Collection Traits
//!
//! - **[`EncodeIterator`]**: Iterate over fields for encoding
//! - **[`DecodeIterator`]**: Iterate over fields for decoding
//! - **[`CollectionEncode`]**: Marker for types with collection-like encoding
//! - **[`CollectionDecode`]**: Marker for types with collection-like decoding
//!
//! ### Zeroization
//!
//! - **[`FastZeroizable`]**: Unified interface for zeroizing types (delegates to `zeroize::Zeroize`)
//!
//! ## Wire Format (Collections)
//!
//! Collections encode with a header for upfront validation:
//!
//! ```text
//! [ num_elements: usize LE ] [ bytes_required: usize LE ] [ elem1 ] [ elem2 ] ... [ elemN ]
//! ```
//!
//! **Why `bytes_required` in header?**
//! - Upfront validation: reject truncated/corrupted data immediately
//! - Exact consumption check: `cursor == bytes_required` prevents partial decode
//! - Streaming support: skip entire collection without decoding elements
//!
//! ## Guards (RAII Zeroization)
//!
//! ### `PrimitiveGuard<T>` (internal)
//!
//! Zeroizes primitives on drop (used internally by `MemEncode` impls for scalars).
//!
//! ### `BytesGuard` (public)
//!
//! ```rust
//! use memcode_core::BytesGuard;
//!
//! let mut sensitive = vec![1u8, 2, 3, 4, 5];
//! {
//!     let guard = BytesGuard::from(sensitive.as_mut_slice());
//!     // Use guard.as_ref() / guard.as_mut()
//! } // guard drops → bytes zeroized
//! ```
//!
//! ## Error Handling
//!
//! All errors implement systematic zeroization:
//!
//! ```rust
//! use memcode_core::{MemEncodeBuf, MemEncode};
//!
//! let mut value = vec![1u8, 2, 3];
//! let mut buf = MemEncodeBuf::new(1); // Too small!
//!
//! let result = value.drain_into(&mut buf);
//!
//! assert!(result.is_err());
//! // Both `value` and `buf` are zeroized on error
//! assert!(value.iter().all(|&b| b == 0));
//! ```
//!
//! **Invariant:** No error path leaves sensitive data unzeroized.
//!
//! ## Integration with Memora
//!
//! `memcode-core` is used throughout the **Memora** framework:
//!
//! ```text
//! memvault (encrypted storage)
//!     ├─> memcrypt (AEAD encryption) ──> uses MemEncodable for plaintext
//!     └─> memcode (this crate)
//!         └─> memzer (guards/zeroization)
//! ```
//!
//! **Example integration:**
//! - `memcrypt::encrypt_mem_encodable<T: MemEncodable>` uses `MemBytesRequired` to pre-allocate
//! - `drain_into()` encodes plaintext → zeroizes source
//! - Encrypt stage operates on encoded bytes → zeroizes after encryption
//!
//! ## Module Organization
//!
//! - [`error`]: Error types ([`MemEncodeError`], [`MemDecodeError`], [`OverflowError`])
//! - [`collections`]: Trait impls and helpers for slices, arrays, `Vec<T>`
//! - [`guards`]: RAII guards for automatic zeroization ([`BytesGuard`])
//! - [`primitives`]: `MemEncode`/`MemDecode` impls for scalars (`u8`, `u16`, `u32`, `u64`, `u128`, `usize`)
//!
//! ## Feature Flags
//!
//! - `test_utils`: Enable test helpers ([`MemCodeTestBreaker`], [`tamper_encoded_bytes_for_tests`])
//!
//! ## Testing
//!
//! Verify encoding/decoding with zeroization:
//!
//! ```rust
//! use memcode_core::{MemEncodeBuf, MemEncode, MemDecode, MemBytesRequired, FastZeroizable};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let mut original = vec![1u8, 2, 3];
//! let size = original.mem_bytes_required()?;
//! let mut buf = MemEncodeBuf::new(size);
//!
//! original.drain_into(&mut buf)?;
//! assert!(original.iter().all(|&b| b == 0)); // Zeroized after encode
//!
//! let mut decoded = Vec::<u8>::new();
//! decoded.drain_from(buf.as_mut_slice())?;
//!
//! assert_eq!(decoded, vec![1, 2, 3]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Safety
//!
//! This crate uses `#![warn(unsafe_op_in_unsafe_fn)]` and minimizes `unsafe` usage.
//! All zeroization relies on RAII (Drop trait) for safety guarantees.
//!
//! ## License
//!
//! GPL-3.0-only

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests;

mod error;
mod guards;
mod mem_encode_buf;
mod primitives;
mod support;
mod traits;

pub use guards::BytesGuard;

/// Trait implementations and helpers for collections (slices, arrays, `Vec<T>`).
///
/// This module provides implementations of encoding/decoding traits for collection types
/// and helper functions for working with heterogeneous collections.
pub mod collections;

pub use error::{MemDecodeError, MemEncodeBufError, MemEncodeError, OverflowError};
pub use mem_encode_buf::MemEncodeBuf;
pub use traits::{
    CollectionDecode, CollectionEncode, DecodeIterator, EncodeIterator, MemBytesRequired,
    MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements, FastZeroizable,
};

#[cfg(feature = "test_utils")]
pub use support::test_utils::memcode_test_breaker::{
    MemCodeTestBreaker, MemCodeTestBreakerBehaviour,
};
#[cfg(feature = "test_utils")]
pub use support::test_utils::utils::tamper_encoded_bytes_for_tests;
