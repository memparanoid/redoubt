// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use super::error::{CoerceError, MemDecodeError, MemEncodeError};
use super::types::MemCodeWord;

use super::word_buf::WordBuf;

pub trait DefaultValue<T> {
    fn default_zero_value() -> T;
    fn cast(v: usize) -> T;
}
pub trait MemCodeTryTakeFrom<T>: Sized {
    fn try_take_from(value: &mut T) -> Result<Self, CoerceError>;
}

pub trait MemDecodeValidateInvariant {
    fn mem_decode_validate_invariant(&self, words: &[MemCodeWord]) -> Result<(), MemDecodeError>;
}

/// Anything that can be *drained into* a word buffer (encode).
pub trait MemDrainEncode {
    /// How many words we will need to write.
    fn mem_encode_required_capacity(&self) -> usize;

    /// Drain all the encoded words into `dst` (must have enough space).
    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), MemEncodeError>;
}

/// Anything that can be *rebuilt by draining from* a word buffer (decode).
pub trait MemDrainDecode {
    /// Drain from `src`, **consuming** (and zeroizing) the words.
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError>;
}
pub(crate) trait TryMemDrainDecode {
    fn try_drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError>;
}
pub trait ZeroizableMemDrainEncode: MemDrainEncode + Zeroize {}
impl<T: Zeroize + MemDrainEncode> ZeroizableMemDrainEncode for T {}

pub trait ZeroizableMemDrainDecode: MemDrainDecode + Zeroize {}
impl<T: Zeroize + MemDrainDecode> ZeroizableMemDrainDecode for T {}
