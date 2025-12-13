// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::codec_buffer::CodecBuffer;
use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref,
    to_decode_zeroize_dyn_mut, to_encode_zeroize_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, DecodeZeroize, Encode, EncodeSlice, EncodeZeroize, PreAlloc,
};

// En memcodec test_breaker.rs
const MAGIC: usize = 0xDEADBEEF;

/// Behavior control for error injection testing in memcodec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecTestBreakerBehaviour {
    /// Normal behavior (no error injection).
    None,
    /// Force `mem_bytes_required()` to return `usize::MAX`.
    BytesRequiredReturnMax,
    /// Force `mem_bytes_required()` to return a specific value.
    BytesRequiredReturn(usize),
    /// Force `mem_bytes_required()` to return an overflow error.
    ForceBytesRequiredOverflow,
    /// Force `encode_into()` to return an error.
    ForceEncodeError,
    /// Force `decode_from()` to return an error.
    ForceDecodeError,
}

impl Default for CodecTestBreakerBehaviour {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Usize {
    /// Controls error injection behavior.
    pub behaviour: CodecTestBreakerBehaviour,
    /// Test data.
    pub data: usize,
}

impl Usize {
    pub fn new(behaviour: CodecTestBreakerBehaviour, data: usize) -> Self {
        Self { behaviour, data }
    }

    pub fn set_behaviour(&mut self, behaviour: CodecTestBreakerBehaviour) {
        self.behaviour = behaviour;
    }
}

impl BytesRequired for Usize {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let fields: [&dyn BytesRequired; 1] = [to_bytes_required_dyn_ref(&self.data)];

        bytes_required_sum(fields.into_iter())
    }
}

impl Encode for Usize {
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        if self.behaviour == CodecTestBreakerBehaviour::ForceEncodeError {
            return Err(EncodeError::IntentionalEncodeError);
        }

        let fields: [&mut dyn EncodeZeroize; 1] = [to_encode_zeroize_dyn_mut(&mut self.data)];

        encode_fields(fields.into_iter(), buf)?;

        Ok(())
    }
}

impl Decode for Usize {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        if self.behaviour == CodecTestBreakerBehaviour::ForceDecodeError {
            return Err(DecodeError::IntentionalDecodeError);
        }

        let fields: [&mut dyn DecodeZeroize; 1] = [to_decode_zeroize_dyn_mut(&mut self.data)];

        decode_fields(fields.into_iter(), buf)?;

        Ok(())
    }
}

impl ZeroizeMetadata for Usize {
    const CAN_BE_BULK_ZEROIZED: bool = true;
}

impl FastZeroizable for Usize {
    fn fast_zeroize(&mut self) {
        self.data.fast_zeroize();
    }
}

impl ZeroizationProbe for Usize {
    fn is_zeroized(&self) -> bool {
        self.data.is_zeroized()
    }
}

/// Test fixture for error injection and edge case testing in memcodec.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CodecTestBreaker {
    /// Controls error injection behavior.
    pub behaviour: CodecTestBreakerBehaviour,
    /// Test data.
    pub usize: Usize,
    /// Magic data, if tampered, decode will fail
    magic: usize,
}

impl Default for CodecTestBreaker {
    fn default() -> Self {
        Self {
            behaviour: CodecTestBreakerBehaviour::None,
            usize: Usize::new(CodecTestBreakerBehaviour::None, 104729),
            magic: MAGIC,
        }
    }
}

impl CodecTestBreaker {
    /// Creates a new test breaker with the specified behavior and data value.
    pub fn new(behaviour: CodecTestBreakerBehaviour, data: usize) -> Self {
        Self {
            behaviour,
            usize: Usize::new(behaviour, data),
            magic: MAGIC,
        }
    }

    /// Creates a new test breaker with default data and specified behavior.
    pub fn with_behaviour(behaviour: CodecTestBreakerBehaviour) -> Self {
        Self {
            behaviour,
            usize: Usize::new(behaviour, 104729),
            magic: MAGIC,
        }
    }

    /// Changes the error injection behavior.
    pub fn set_behaviour(&mut self, behaviour: CodecTestBreakerBehaviour) {
        self.behaviour = behaviour;
        self.usize.set_behaviour(behaviour);
    }
}

impl BytesRequired for CodecTestBreaker {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        match &self.behaviour {
            CodecTestBreakerBehaviour::BytesRequiredReturnMax => Ok(usize::MAX),
            CodecTestBreakerBehaviour::BytesRequiredReturn(n) => Ok(*n),
            CodecTestBreakerBehaviour::ForceBytesRequiredOverflow => Err(OverflowError {
                reason: "CodecTestBreaker forced overflow".into(),
            }),
            _ => {
                let fields: [&dyn BytesRequired; 2] = [
                    to_bytes_required_dyn_ref(&self.usize),
                    to_bytes_required_dyn_ref(&self.magic),
                ];

                bytes_required_sum(fields.into_iter())
            }
        }
    }
}

impl Encode for CodecTestBreaker {
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let fields: [&mut dyn EncodeZeroize; 2] = [
            to_encode_zeroize_dyn_mut(&mut self.usize),
            to_encode_zeroize_dyn_mut(&mut self.magic),
        ];

        encode_fields(fields.into_iter(), buf)?;

        Ok(())
    }
}

impl Decode for CodecTestBreaker {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let fields: [&mut dyn DecodeZeroize; 2] = [
            to_decode_zeroize_dyn_mut(&mut self.usize),
            to_decode_zeroize_dyn_mut(&mut self.magic),
        ];

        decode_fields(fields.into_iter(), buf)?;

        if self.magic != MAGIC {
            return Err(DecodeError::IntentionalDecodeError);
        }

        Ok(())
    }
}

impl EncodeSlice for CodecTestBreaker {
    fn encode_slice_into(slice: &mut [Self], buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }
        Ok(())
    }
}

impl DecodeSlice for CodecTestBreaker {
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }
        Ok(())
    }
}

impl PreAlloc for CodecTestBreaker {
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, _size: usize) {
        // No-op: CodecTestBreaker does not need to prealloc.
    }
}

impl ZeroizeMetadata for CodecTestBreaker {
    /// Keep CAN_BE_BULK_ZEROIZED = false to test recursive zeroization path.
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for CodecTestBreaker {
    fn fast_zeroize(&mut self) {
        self.usize.fast_zeroize();
        self.magic.fast_zeroize();
    }
}

impl ZeroizationProbe for CodecTestBreaker {
    fn is_zeroized(&self) -> bool {
        (self.usize.is_zeroized()) & (self.magic.is_zeroized())
    }
}
