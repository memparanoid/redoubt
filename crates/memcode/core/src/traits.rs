// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::error::{MemDecodeError, MemEncodeError, OverflowError};
use super::mem_encode_buf::MemEncodeBuf;

pub trait Zeroizable {
    fn self_zeroize(&mut self);
}
pub trait MemEncode: Zeroizable {
    fn drain_into(&mut self, buf: &mut MemEncodeBuf) -> Result<(), MemEncodeError>;
}

pub trait MemDecode: Zeroizable {
    /// Decodes data from bytes and returns the number of bytes consumed.
    ///
    /// Precondition that will be checked during runtime: bytes.len() must be >= the required bytes for this type.
    /// The implementation will consume only what it needs and return that amount.
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, MemDecodeError>;
}

pub trait MemNumElements {
    fn mem_num_elements(&self) -> usize;
}

pub trait MemBytesRequired {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError>;
}

pub trait MemEncodable: MemEncode + MemNumElements + MemBytesRequired {}
pub trait MemDecodable: MemDecode + MemBytesRequired {}

pub trait EncodeIterator {
    fn encode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemEncodable>;
}

pub trait DecodeIterator {
    fn decode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemDecodable>;
}

pub trait CollectionEncode: EncodeIterator + MemEncodable {}
pub trait CollectionDecode: DecodeIterator + MemDecodable {
    fn prepare_with_num_elements(&mut self, num_elements: usize) -> Result<(), MemDecodeError>;
}
