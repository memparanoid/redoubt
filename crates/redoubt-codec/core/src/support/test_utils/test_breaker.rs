// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref,
    to_decode_zeroize_dyn_mut, to_encode_zeroize_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, DecodeZeroize, Encode, EncodeSlice, EncodeZeroize, PreAlloc,
};

// Test breaker for redoubt-codec
const MAGIC: usize = 0xDEADBEEF;

/// Behavior control for error injection testing in redoubt-codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedoubtCodecTestBreakerBehaviour {
    /// Normal behavior (no error injection).
    None,
    /// Force `encode_bytes_required()` to return `usize::MAX`.
    BytesRequiredReturnMax,
    /// Force `encode_bytes_required()` to return a specific value.
    BytesRequiredReturn(usize),
    /// Force `encode_bytes_required()` to return an overflow error.
    ForceBytesRequiredOverflow,
    /// Force `encode_into()` to return an error.
    ForceEncodeError,
    /// Force `decode_from()` to return an error.
    ForceDecodeError,
}

impl Default for RedoubtCodecTestBreakerBehaviour {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Usize {
    /// Controls error injection behavior.
    pub behaviour: RedoubtCodecTestBreakerBehaviour,
    /// Test data.
    pub data: usize,
}

impl Usize {
    pub fn new(behaviour: RedoubtCodecTestBreakerBehaviour, data: usize) -> Self {
        Self { behaviour, data }
    }

    pub fn set_behaviour(&mut self, behaviour: RedoubtCodecTestBreakerBehaviour) {
        self.behaviour = behaviour;
    }
}

impl BytesRequired for Usize {
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        let fields: [&dyn BytesRequired; 1] = [to_bytes_required_dyn_ref(&self.data)];

        bytes_required_sum(fields.into_iter())
    }
}

impl Encode for Usize {
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        if self.behaviour == RedoubtCodecTestBreakerBehaviour::ForceEncodeError {
            return Err(EncodeError::IntentionalEncodeError);
        }

        let fields: [&mut dyn EncodeZeroize; 1] = [to_encode_zeroize_dyn_mut(&mut self.data)];

        encode_fields(fields.into_iter(), buf)?;

        Ok(())
    }
}

impl Decode for Usize {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        if self.behaviour == RedoubtCodecTestBreakerBehaviour::ForceDecodeError {
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

/// Test fixture for error injection and edge case testing in redoubt-codec.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RedoubtCodecTestBreaker {
    /// Controls error injection behavior.
    pub behaviour: RedoubtCodecTestBreakerBehaviour,
    /// Test data.
    pub usize: Usize,
    /// Magic data, if tampered, decode will fail
    magic: usize,
}

impl Default for RedoubtCodecTestBreaker {
    fn default() -> Self {
        Self {
            behaviour: RedoubtCodecTestBreakerBehaviour::None,
            usize: Usize::new(RedoubtCodecTestBreakerBehaviour::None, 104729),
            magic: MAGIC,
        }
    }
}

impl RedoubtCodecTestBreaker {
    /// Creates a new test breaker with the specified behavior and data value.
    pub fn new(behaviour: RedoubtCodecTestBreakerBehaviour, data: usize) -> Self {
        Self {
            behaviour,
            usize: Usize::new(behaviour, data),
            magic: MAGIC,
        }
    }

    /// Creates a new test breaker with default data and specified behavior.
    pub fn with_behaviour(behaviour: RedoubtCodecTestBreakerBehaviour) -> Self {
        Self {
            behaviour,
            usize: Usize::new(behaviour, 104729),
            magic: MAGIC,
        }
    }

    /// Changes the error injection behavior.
    pub fn set_behaviour(&mut self, behaviour: RedoubtCodecTestBreakerBehaviour) {
        self.behaviour = behaviour;
        self.usize.set_behaviour(behaviour);
    }
}

impl BytesRequired for RedoubtCodecTestBreaker {
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        match &self.behaviour {
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturnMax => Ok(usize::MAX),
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturn(n) => Ok(*n),
            RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow => Err(OverflowError {
                reason: "RedoubtCodecTestBreaker forced overflow".into(),
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

impl Encode for RedoubtCodecTestBreaker {
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let fields: [&mut dyn EncodeZeroize; 2] = [
            to_encode_zeroize_dyn_mut(&mut self.usize),
            to_encode_zeroize_dyn_mut(&mut self.magic),
        ];

        encode_fields(fields.into_iter(), buf)?;

        Ok(())
    }
}

impl Decode for RedoubtCodecTestBreaker {
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

impl EncodeSlice for RedoubtCodecTestBreaker {
    fn encode_slice_into(
        slice: &mut [Self],
        buf: &mut RedoubtCodecBuffer,
    ) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }
        Ok(())
    }
}

impl DecodeSlice for RedoubtCodecTestBreaker {
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }
        Ok(())
    }
}

impl PreAlloc for RedoubtCodecTestBreaker {
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, _size: usize) {
        // No-op: RedoubtCodecTestBreaker does not need to prealloc.
    }
}

impl ZeroizeMetadata for RedoubtCodecTestBreaker {
    /// Keep CAN_BE_BULK_ZEROIZED = false to test recursive zeroization path.
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for RedoubtCodecTestBreaker {
    fn fast_zeroize(&mut self) {
        self.usize.fast_zeroize();
        self.magic.fast_zeroize();
    }
}

impl ZeroizationProbe for RedoubtCodecTestBreaker {
    fn is_zeroized(&self) -> bool {
        (self.usize.is_zeroized()) & (self.magic.is_zeroized())
    }
}
