// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations for primitive integer types.
//!
//! This module provides `MemEncode`, `MemDecode`, and `Zeroizable` implementations
//! for Rust's primitive unsigned integer types: `u8`, `u16`, `u32`, `u64`, `u128`.
//!
//! # Wire Format
//!
//! All primitives are encoded in **little-endian** format:
//!
//! - `u8`: 1 byte
//! - `u16`: 2 bytes (LE)
//! - `u32`: 4 bytes (LE)
//! - `u64`: 8 bytes (LE)
//! - `u128`: 16 bytes (LE)
//!
//! # Zeroization
//!
//! All encoding/decoding operations zeroize the source value after copying.
//! This is enforced via [`PrimitiveGuard`] (internal) and [`BytesGuard`].
//!
//! # Example
//!
//! ```rust
//! use memcode_core::{MemEncodeBuf, MemEncode, MemDecode, MemBytesRequired};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let mut value = 0xdeadbeef_u32;
//!
//! // Encode
//! let size = value.mem_bytes_required()?;
//! let mut buf = MemEncodeBuf::new(size);
//! value.drain_into(&mut buf)?;
//!
//! assert_eq!(value, 0); // Source zeroized
//!
//! // Decode
//! let mut decoded = 0u32;
//! decoded.drain_from(buf.as_mut_slice())?;
//!
//! assert_eq!(decoded, 0xdeadbeef);
//! # Ok(())
//! # }
//! ```

use zeroize::Zeroize;

use super::guards::{BytesGuard, PrimitiveGuard};

macro_rules! impl_mem_encode_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::MemEncodable for $ty {}

            impl $crate::traits::MemNumElements for $ty {
                #[inline(always)]
                fn mem_num_elements(&self) -> usize {
                    1
                }
            }

            impl $crate::traits::MemBytesRequired for $ty {
                #[inline(always)]
                fn mem_bytes_required(&self) -> Result<usize, $crate::error::OverflowError> {
                    Ok(core::mem::size_of::<$ty>())
                }
            }

            impl $crate::traits::MemEncode for $ty {
                #[inline(always)]
                fn drain_into(&mut self, buf: &mut $crate::mem_encode_buf::MemEncodeBuf) -> Result<(), $crate::error::MemEncodeError> {
                    let guard = PrimitiveGuard::from(self);
                    let mut bytes = guard.as_ref().to_le_bytes();

                    buf.drain_bytes(&mut bytes)?;

                    Ok(())
                }
            }
        )*
    };
}

macro_rules! impl_mem_decode_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::MemDecodable for $ty {}

            impl $crate::traits::MemDecode for $ty {
                fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, $crate::error::MemDecodeError> {
                    let bytes_required = core::mem::size_of::<Self>();

                    if bytes.len() < bytes_required {
                        self.zeroize();
                        bytes.zeroize();
                        return Err($crate::error::MemDecodeError::LengthMismatch {
                            expected: bytes_required,
                            got: bytes.len()
                        });
                    }

                    let consumed_bytes_guard = BytesGuard::from(&mut bytes[0..bytes_required]);

                    let mut le_bytes = [0u8; core::mem::size_of::<$ty>()];
                    le_bytes.copy_from_slice(consumed_bytes_guard.as_ref());

                    *self = <$ty>::from_le_bytes(le_bytes);

                    le_bytes.zeroize();

                    Ok(bytes_required)
                }
            }
        )*
    };
}

macro_rules! impl_zeroizable_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::Zeroizable for $ty {
                #[inline(always)]
                fn self_zeroize(&mut self) {
                    self.zeroize();
                }
            }
        )*
    };
}

impl_mem_encode_for_primitives!(u8, u16, u32, u64, u128);
impl_mem_decode_for_primitives!(u8, u16, u32, u64, u128);
impl_zeroizable_for_primitives!(u8, u16, u32, u64, u128);
