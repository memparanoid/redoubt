// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::collections;
use crate::error::{MemDecodeError, MemEncodeError, OverflowError};
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{
    CollectionDecode, CollectionEncode, DecodeIterator, EncodeIterator, MemBytesRequired,
    MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements, Zeroizable,
};

/// Behavior control for error injection testing in MemCode.
///
/// Allows simulating various error conditions during encoding/decoding to test error handling.
#[derive(Debug, Zeroize, PartialEq, Eq)]
pub enum MemCodeTestBreakerBehaviour {
    /// Normal behavior (no error injection).
    None,
    /// Force `mem_bytes_required()` to return a specific value.
    ForceBytesRequiredUsize(usize),
    /// Force `mem_bytes_required()` to return `usize::MAX`.
    ForceBytesRequiredUsizeMax,
    /// Force `mem_bytes_required()` to return an overflow error.
    ForceBytesRequiredOverflowError,
    /// Force `drain_from()` to return a decode error.
    ForceDecodeError,
    /// Force `drain_from()` to return a specific number of consumed bytes.
    ForceDecodeReturnBytes(usize),
    /// Force `drain_into()` to return an encode error.
    ForceEncodeError,
    /// Force `prepare_with_num_elements()` to return an error.
    ForcePrepareWithNumElementsError,
}

/// Test fixture for error injection and edge case testing in MemCode.
///
/// Contains a large `Vec<u16>` (65535 elements) and configurable behavior for simulating errors.
#[derive(Debug, Zeroize)]
pub struct MemCodeTestBreaker {
    /// Controls error injection behavior.
    pub behaviour: MemCodeTestBreakerBehaviour,
    /// Test data buffer (default: 65535 elements of `u16::MAX`).
    pub data: Vec<u16>,
}

impl Default for MemCodeTestBreaker {
    fn default() -> Self {
        Self {
            behaviour: MemCodeTestBreakerBehaviour::None,
            data: Self::create_data_with_pattern(u16::MAX as usize, u16::MAX),
        }
    }
}

impl MemCodeTestBreaker {
    /// Creates a vector filled with a repeating pattern.
    pub fn create_data_with_pattern(size: usize, pattern: u16) -> Vec<u16> {
        let mut data = Vec::with_capacity(size);
        data.resize_with(size, || pattern);

        data
    }

    /// Creates a new test breaker with the specified behavior.
    pub fn new(behaviour: MemCodeTestBreakerBehaviour) -> Self {
        Self {
            behaviour,
            data: Self::create_data_with_pattern(u16::MAX as usize, u16::MAX),
        }
    }

    /// Restores the data buffer to its maximum size (65535 elements of `u16::MAX`).
    pub fn restore_to_max(&mut self) {
        self.data = Self::create_data_with_pattern(u16::MAX as usize, u16::MAX);
    }

    /// Changes the error injection behavior.
    pub fn change_behaviour(&mut self, behaviour: MemCodeTestBreakerBehaviour) {
        self.behaviour = behaviour;
    }

    /// Checks if the data buffer is fully zeroized.
    pub fn is_zeroized(&self) -> bool {
        self.data.iter().all(|b| *b == 0)
    }
}

impl Zeroizable for MemCodeTestBreaker {
    #[inline(always)]
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl MemNumElements for MemCodeTestBreaker {
    fn mem_num_elements(&self) -> usize {
        2
    }
}

impl MemBytesRequired for MemCodeTestBreaker {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        match &self.behaviour {
            MemCodeTestBreakerBehaviour::ForceBytesRequiredUsizeMax => Ok(usize::MAX),
            MemCodeTestBreakerBehaviour::ForceBytesRequiredUsize(u) => Ok(*u),
            MemCodeTestBreakerBehaviour::ForceBytesRequiredOverflowError => Err(OverflowError {
                reason: "Overflow while computing mem_bytes_required() on MemCodeTestBreaker"
                    .into(),
            }),
            _ => {
                let collection: [&dyn MemBytesRequired; 1] =
                    [collections::to_bytes_required_dyn_ref(&self.data)];
                collections::mem_bytes_required(&mut collection.into_iter())
            }
        }
    }
}

impl MemEncode for MemCodeTestBreaker {
    fn drain_into(&mut self, buf: &mut MemEncodeBuf) -> Result<(), MemEncodeError> {
        if self.behaviour == MemCodeTestBreakerBehaviour::ForceEncodeError {
            return Err(MemEncodeError::IntentionalEncodeError);
        }

        collections::drain_into(buf, self)
    }
}

impl MemDecode for MemCodeTestBreaker {
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, MemDecodeError> {
        if self.behaviour == MemCodeTestBreakerBehaviour::ForceDecodeError {
            return Err(MemDecodeError::IntentionalDecodeError);
        }

        let result = collections::drain_from(bytes, self);

        if let MemCodeTestBreakerBehaviour::ForceDecodeReturnBytes(u) = self.behaviour {
            return Ok(u);
        }

        result
    }
}

impl DecodeIterator for MemCodeTestBreaker {
    fn decode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemDecodable> {
        let collection: [&mut dyn MemDecodable; 1] =
            [collections::to_decode_dyn_mut(&mut self.data)];
        collection.into_iter()
    }
}

impl EncodeIterator for MemCodeTestBreaker {
    fn encode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemEncodable> {
        let collection: [&mut dyn MemEncodable; 1] =
            [collections::to_encode_dyn_mut(&mut self.data)];
        collection.into_iter()
    }
}

impl MemEncodable for MemCodeTestBreaker {}
impl MemDecodable for MemCodeTestBreaker {}
impl CollectionEncode for MemCodeTestBreaker {}
impl CollectionDecode for MemCodeTestBreaker {
    fn prepare_with_num_elements(&mut self, _size: usize) -> Result<(), MemDecodeError> {
        if self.behaviour == MemCodeTestBreakerBehaviour::ForcePrepareWithNumElementsError {
            return Err(MemDecodeError::IntentionalPrepareWithNumElementsError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcode_test_breaker_default() {
        let test_breaker = MemCodeTestBreaker::default();
        assert!(!test_breaker.is_zeroized());
        assert!(test_breaker.behaviour == MemCodeTestBreakerBehaviour::None);
    }
}
