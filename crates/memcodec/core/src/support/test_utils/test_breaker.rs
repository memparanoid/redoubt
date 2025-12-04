// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::ZeroizationProbe;
use zeroize::Zeroize;

use crate::codec_buffer::CodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, FastZeroizable, PreAlloc,
    ZeroizeMetadata,
};

/// Behavior control for error injection testing in memcodec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TestBreakerBehaviour {
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

impl Default for TestBreakerBehaviour {
    fn default() -> Self {
        Self::None
    }
}

/// Test fixture for error injection and edge case testing in memcodec.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TestBreaker {
    /// Controls error injection behavior.
    pub behaviour: TestBreakerBehaviour,
    /// Test data.
    pub data: usize,
}

impl Zeroize for TestBreaker {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Default for TestBreaker {
    fn default() -> Self {
        Self {
            behaviour: TestBreakerBehaviour::None,
            data: 104729,
        }
    }
}

impl TestBreaker {
    /// Creates a new test breaker with the specified behavior and data value.
    pub fn new(behaviour: TestBreakerBehaviour, data: usize) -> Self {
        Self { behaviour, data }
    }

    /// Creates a new test breaker with default data and specified behavior.
    pub fn with_behaviour(behaviour: TestBreakerBehaviour) -> Self {
        Self {
            behaviour,
            ..Default::default()
        }
    }

    /// Changes the error injection behavior.
    pub fn set_behaviour(&mut self, behaviour: TestBreakerBehaviour) {
        self.behaviour = behaviour;
    }
}

impl BytesRequired for TestBreaker {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        match &self.behaviour {
            TestBreakerBehaviour::BytesRequiredReturnMax => Ok(usize::MAX),
            TestBreakerBehaviour::BytesRequiredReturn(n) => Ok(*n),
            TestBreakerBehaviour::ForceBytesRequiredOverflow => Err(OverflowError {
                reason: "TestBreaker forced overflow".into(),
            }),
            _ => self.data.mem_bytes_required(),
        }
    }
}

impl Encode for TestBreaker {
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        if self.behaviour == TestBreakerBehaviour::ForceEncodeError {
            return Err(EncodeError::IntentionalEncodeError);
        }
        self.data.encode_into(buf)
    }
}

impl Decode for TestBreaker {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        if self.behaviour == TestBreakerBehaviour::ForceDecodeError {
            return Err(DecodeError::IntentionalDecodeError);
        }
        self.data.decode_from(buf)
    }
}

impl EncodeSlice for TestBreaker {
    fn encode_slice_into(slice: &mut [Self], buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }
        Ok(())
    }
}

impl DecodeSlice for TestBreaker {
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }
        Ok(())
    }
}

impl PreAlloc for TestBreaker {
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, _size: usize) {
        // No-op: TestBreaker does not need to prealloc.
    }
}

impl ZeroizeMetadata for TestBreaker {
    /// Keep CAN_BE_BULK_ZEROIZED = false to test recursive zeroization path.
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for TestBreaker {
    fn fast_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for TestBreaker {
    fn is_zeroized(&self) -> bool {
        self.data == 0
    }
}
