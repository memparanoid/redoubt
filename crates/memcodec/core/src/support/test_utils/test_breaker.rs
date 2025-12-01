// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
use zeroize::Zeroize;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, CodecZeroize, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc};

/// Behavior control for error injection testing in memcodec.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
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
#[derive(Debug, Clone, Zeroize)]
pub struct TestBreaker {
    /// Controls error injection behavior.
    pub behaviour: TestBreakerBehaviour,
    /// Test data buffer.
    pub data: Vec<u8>,
}

impl Default for TestBreaker {
    fn default() -> Self {
        Self {
            behaviour: TestBreakerBehaviour::None,
            data: vec![0xAA; 1024],
        }
    }
}

impl TestBreaker {
    /// Creates a new test breaker with the specified behavior and data size.
    pub fn new(behaviour: TestBreakerBehaviour, size: usize) -> Self {
        Self {
            behaviour,
            data: vec![0xAA; size],
        }
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

    /// Checks if the data buffer is fully zeroized.
    pub fn is_zeroized(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
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
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
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

impl PartialEq for TestBreaker {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for TestBreaker {}

impl EncodeSlice for TestBreaker {
    fn encode_slice_into(slice: &mut [Self], buf: &mut Buffer) -> Result<(), EncodeError> {
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
        // No-op: collection uses Default::default() when ZERO_INIT = false
    }
}

impl CodecZeroize for TestBreaker {
    /// TestBreaker is complex (contains Vec<u8>), cannot be fast-zeroized.
    const FAST_ZEROIZE: bool = false;

    fn codec_zeroize(&mut self) {
        self.data.codec_zeroize();
    }
}
