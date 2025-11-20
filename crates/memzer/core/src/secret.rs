// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt;

use zeroize::Zeroize;

use super::assert::assert_zeroize_on_drop;
use super::drop_sentinel::DropSentinel;
use super::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};
use crate::collections::{
    collection_zeroed, to_zeroizable_dyn_mut, to_zeroization_probe_dyn_ref, zeroize_collection,
};
#[cfg(any(test, feature = "memcode"))]
use memcode_core::{
    CollectionDecode, CollectionEncode, DecodeIterator, EncodeIterator, MemBytesRequired,
    MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements,
    Zeroizable as MemCodeZeroizable, collections,
};

#[derive(Zeroize, Default, PartialEq, Eq)]
#[zeroize(drop)]
pub struct Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    inner: T,
    __drop_sentinel: DropSentinel,
}

impl<T> fmt::Debug for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED Secret]")
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    pub fn from(inner: T) -> Self {
        Self {
            inner,
            __drop_sentinel: DropSentinel::default(),
        }
    }

    pub fn expose(&self) -> &T {
        &self.inner
    }

    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> Zeroizable for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn self_zeroize(&mut self) {
        let elements: [&mut dyn Zeroizable; 1] = [to_zeroizable_dyn_mut(&mut self.inner)];
        zeroize_collection(&mut elements.into_iter());
    }
}

impl<T> AssertZeroizeOnDrop for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn clone_drop_sentinel(&self) -> crate::drop_sentinel::DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl<T> ZeroizationProbe for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        let elements: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&self.inner)];
        collection_zeroed(&mut elements.into_iter())
    }
}

// Memcode feature
#[cfg(any(test, feature = "memcode"))]
impl<T> MemCodeZeroizable for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> MemNumElements for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemBytesRequired,
{
    #[inline(always)]
    fn mem_num_elements(&self) -> usize {
        2
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> MemBytesRequired for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemBytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, memcode_core::OverflowError> {
        let collection: [&dyn MemBytesRequired; 2] = [
            collections::to_bytes_required_dyn_ref(&self.__drop_sentinel),
            collections::to_bytes_required_dyn_ref(&self.inner),
        ];

        // `collection.into_iter()` produces &dyn MemBytesRequired directly,
        // avoiding the double reference (&&) that `.iter()` would create.
        // No values are copied - we're just iterating over references from the array.
        collections::mem_bytes_required(&mut collection.into_iter())
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> MemEncode for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable,
{
    fn drain_into(
        &mut self,
        buf: &mut memcode_core::MemEncodeBuf,
    ) -> Result<(), memcode_core::MemEncodeError> {
        collections::drain_into(buf, self)
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> MemDecode for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemDecodable,
{
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, memcode_core::MemDecodeError> {
        collections::drain_from(bytes, self)
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> DecodeIterator for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemDecodable,
{
    fn decode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemDecodable> {
        let collection: [&mut dyn MemDecodable; 2] = [
            collections::to_decode_dyn_mut(&mut self.__drop_sentinel),
            collections::to_decode_dyn_mut(&mut self.inner),
        ];

        collection.into_iter()
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> EncodeIterator for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable,
{
    fn encode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemEncodable> {
        let collection: [&mut dyn MemEncodable; 2] = [
            collections::to_encode_dyn_mut(&mut self.__drop_sentinel),
            collections::to_encode_dyn_mut(&mut self.inner),
        ];
        collection.into_iter()
    }
}

#[cfg(any(test, feature = "memcode"))]
impl<T> MemEncodable for Secret<T> where T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable {}
#[cfg(any(test, feature = "memcode"))]
impl<T> MemDecodable for Secret<T> where T: Zeroize + Zeroizable + ZeroizationProbe + MemDecodable {}
#[cfg(any(test, feature = "memcode"))]
impl<T> CollectionEncode for Secret<T> where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable
{
}
#[cfg(any(test, feature = "memcode"))]
impl<T> CollectionDecode for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemDecodable,
{
    fn prepare_with_num_elements(
        &mut self,
        size: usize,
    ) -> Result<(), memcode_core::MemDecodeError> {
        collections::mem_decode_assert_num_elements(2, size)
    }
}
