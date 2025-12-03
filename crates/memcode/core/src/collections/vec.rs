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
    drain_from, drain_into, mem_bytes_required, to_bytes_required_dyn_ref, to_decode_dyn_mut,
    to_encode_dyn_mut,
};

// === === === === === === === === === ===
// Vec<T>
// === === === === === === === === === ===
impl<T> Zeroizable for Vec<T>
where
    T: Zeroizable + Zeroize,
{
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl<T> MemNumElements for Vec<T>
where
    T: Zeroize + MemNumElements,
{
    fn mem_num_elements(&self) -> usize {
        self.len()
    }
}
impl<T> MemBytesRequired for Vec<T>
where
    T: Zeroize + MemBytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        mem_bytes_required(&mut self.iter().map(to_bytes_required_dyn_ref))
    }
}

impl<T> MemDecode for Vec<T>
where
    T: Default + Zeroize + MemDecodable,
{
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, MemDecodeError> {
        drain_from(bytes, self)
    }
}

impl<T> MemEncode for Vec<T>
where
    T: Zeroize + MemEncodable,
{
    fn drain_into(&mut self, buf: &mut MemEncodeBuf) -> Result<(), MemEncodeError> {
        drain_into(buf, self)
    }
}

impl<T> DecodeIterator for Vec<T>
where
    T: MemDecodable,
{
    fn decode_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut (dyn MemDecodable + 'a)> {
        self.iter_mut().map(to_decode_dyn_mut)
    }
}

impl<T> EncodeIterator for Vec<T>
where
    T: MemEncodable,
{
    fn encode_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut (dyn MemEncodable + 'a)> {
        self.iter_mut().map(to_encode_dyn_mut)
    }
}

impl<T> MemEncodable for Vec<T> where T: Zeroize + MemEncodable {}
impl<T> CollectionEncode for Vec<T> where T: Zeroize + MemEncodable {}
impl<T> MemDecodable for Vec<T> where T: Default + Zeroize + MemDecodable {}
impl<T> CollectionDecode for Vec<T>
where
    T: Default + Zeroize + MemDecodable,
{
    fn prepare_with_num_elements(&mut self, num_elements: usize) -> Result<(), MemDecodeError> {
        // SAFETY: `Zeroize::zeroize()` for `Vec<T>` clears BOTH active elements [0..len()]
        // AND spare capacity [len()..capacity()]. This is verified by test
        // `memzer_core::tests::utils::test_is_vec_fully_zeroized`.
        //
        // This makes the subsequent `resize_with()` safe: we're expanding over
        // a fully zeroized allocation, preventing leaks of previous sensitive data.
        self.zeroize();
        self.shrink_to_fit();
        self.resize_with(num_elements, || T::default());

        Ok(())
    }
}
