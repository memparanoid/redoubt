// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::error::{CodecBufferError, DecodeBufferError, DecodeError, EncodeError, OverflowError};

pub trait BytesRequired {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError>;
}

pub(crate) trait TryEncode: Encode + Sized {
    fn try_encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError>;
}

pub trait Encode {
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError>;
}

/// Encode a slice of elements into the buffer.
/// - Primitives: NO zeroize (collection handles it)
/// - Collections: YES zeroize (handle their own cleanup)
pub(crate) trait EncodeSlice: Encode + Sized {
    fn encode_slice_into(slice: &mut [Self], buf: &mut Buffer) -> Result<(), EncodeError>;
}

// @TODO: Doc why this trait is useful
pub(crate) trait TryDecode {
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

pub trait Decode {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

/// Decode a slice of elements from the buffer.
/// - Primitives: NO zeroize (collection handles it)
/// - Collections: YES zeroize (handle their own cleanup)
pub(crate) trait DecodeSlice: Decode + Sized {
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

pub trait CodecBuffer {
    fn write<T>(&mut self, src: &mut T) -> Result<(), CodecBufferError>;
    fn write_slice<T>(&mut self, src: &mut [T]) -> Result<(), CodecBufferError>;
}

pub trait DecodeBuffer {
    fn read_usize(&mut self, dst: &mut usize) -> Result<(), DecodeBufferError>;
    fn read<T>(&mut self, dst: &mut T) -> Result<(), DecodeBufferError>;
    fn read_slice<T>(&mut self, dst: &mut [T]) -> Result<(), DecodeBufferError>;
}

/// Pre-allocation trait for collections.
///
/// `ZERO_INIT` indicates if the type can be safely initialized by zeroing memory.
/// - `true`: Use fast memset + set_len (primitives)
/// - `false`: Use Default::default() for each element (complex types)
pub(crate) trait PreAlloc: Default {
    const ZERO_INIT: bool;
    fn prealloc(&mut self, size: usize);
}

/// Fast zeroization indicator trait.
///
/// `FAST_ZEROIZE` indicates if the type can be zeroed with a fast memset.
/// - `true`: Primitives (no internal pointers, memset is safe and sufficient)
/// - `false`: Complex types like Vec (need recursive zeroization due to internal pointers)
///
/// For `Vec<T>`:
/// - `FAST_ZEROIZE` is ALWAYS `false` (Vec has ptr/len/capacity)
/// - If `T::FAST_ZEROIZE` is `true`, memset the contents + spare capacity
/// - If `T::FAST_ZEROIZE` is `false`, recurse into each element + memset spare capacity
pub trait FastZeroize {
    const FAST_ZEROIZE: bool;
}

/// Zeroization trait for codec types (dyn-compatible).
pub trait CodecZeroize {
    fn codec_zeroize(&mut self);
}

/// Blanket impl when zeroize feature is disabled - everything is a no-op.
#[cfg(not(feature = "zeroize"))]
impl<T> FastZeroize for T {
    const FAST_ZEROIZE: bool = true;
}

#[cfg(not(feature = "zeroize"))]
impl<T> CodecZeroize for T {
    fn codec_zeroize(&mut self) {}
}

/// Supertrait combining Encode + CodecZeroize for derive macro helpers.
/// Used by encode_fields to zeroize all fields on error.
pub trait EncodeZeroize: Encode + CodecZeroize {}
impl<T: Encode + CodecZeroize> EncodeZeroize for T {}

/// Supertrait combining Decode + CodecZeroize for derive macro helpers.
/// Used by decode_fields to zeroize all fields on error.
pub trait DecodeZeroize: Decode + CodecZeroize {}
impl<T: Decode + CodecZeroize> DecodeZeroize for T {}
