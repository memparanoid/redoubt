// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::{MemDecodeError, MemEncodeError, OverflowError};
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{
    CollectionDecode, CollectionEncode, DecodeIterator, EncodeIterator, MemBytesRequired,
    MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements, Zeroizable,
};

use super::helpers::{
    drain_from, drain_into, mem_bytes_required, mem_decode_assert_num_elements,
    to_bytes_required_dyn_ref, to_decode_dyn_mut, to_encode_dyn_mut, to_zeroizable_dyn_mut,
    zeroize_collection_iter_mut,
};

// === === === === === === === === === ===
// [T]
// === === === === === === === === === ===
impl<T> Zeroizable for [T]
where
    T: Zeroizable + Zeroize,
{
    fn self_zeroize(&mut self) {
        zeroize_collection_iter_mut(&mut self.iter_mut().map(to_zeroizable_dyn_mut));
    }
}

impl<T> MemNumElements for [T]
where
    T: Zeroize + MemNumElements,
{
    fn mem_num_elements(&self) -> usize {
        self.len()
    }
}

impl<T> MemBytesRequired for [T]
where
    T: Zeroize + MemBytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        mem_bytes_required(&mut self.iter().map(to_bytes_required_dyn_ref))
    }
}

impl<T> MemDecode for [T]
where
    T: Zeroize + MemDecodable,
{
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, MemDecodeError> {
        drain_from(bytes, self)
    }
}

impl<T> MemEncode for [T]
where
    T: Zeroize + MemEncodable,
{
    fn drain_into(&mut self, buf: &mut MemEncodeBuf) -> Result<(), MemEncodeError> {
        drain_into(buf, self)
    }
}

impl<T> DecodeIterator for [T]
where
    T: MemDecodable,
{
    fn decode_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut (dyn MemDecodable + 'a)> {
        self.iter_mut().map(to_decode_dyn_mut)
    }
}

impl<T> EncodeIterator for [T]
where
    T: MemEncodable,
{
    fn encode_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut (dyn MemEncodable + 'a)> {
        self.iter_mut().map(to_encode_dyn_mut)
    }
}

impl<T> MemEncodable for [T] where T: Zeroize + MemEncodable {}
impl<T> CollectionEncode for [T] where T: Zeroize + MemEncodable {}
impl<T> MemDecodable for [T] where T: Zeroize + MemDecodable {}
impl<T> CollectionDecode for [T]
where
    T: Zeroize + MemDecodable,
{
    fn prepare_with_num_elements(&mut self, num_elements: usize) -> Result<(), MemDecodeError> {
        mem_decode_assert_num_elements(self.len(), num_elements)
    }
}
