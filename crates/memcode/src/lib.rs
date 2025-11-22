// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memcode
//!
//! Allocation-free, zeroizing serialization for protecting sensitive data.
//!
//! This is a re-export crate combining [`memcode-core`] and [`memcode-derive`].
//!
//! ## Quick Start
//!
//! ```rust
//! use memcode::{MemCodec, MemEncodeBuf, MemEncode, MemDecode, MemBytesRequired};
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
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut data = Data {
//!     field_a: vec![1, 2, 3],
//!     field_b: [0u8; 32],
//!     field_c: 42,
//! };
//!
//! // Calculate size upfront (no allocation yet)
//! let size = data.mem_bytes_required()?;
//!
//! // Pre-allocate buffer with exact size
//! let mut buf = MemEncodeBuf::new(size);
//!
//! // Encode (moves data, zeroizes source)
//! data.drain_into(&mut buf)?;
//!
//! // data is now zeroized
//! # Ok(())
//! # }
//! ```
//!
//! ## Documentation
//!
//! See [`memcode-core`] for detailed documentation.
//!
//! [`memcode-core`]: https://docs.rs/memcode-core
//! [`memcode-derive`]: https://docs.rs/memcode-derive

pub use memcode_core::*;
pub use memcode_derive::*;
