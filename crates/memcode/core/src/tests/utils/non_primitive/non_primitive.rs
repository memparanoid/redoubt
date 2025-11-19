// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use insta::assert_snapshot;
use zeroize::Zeroize;

use crate::error::{CoerceError, MemDecodeError, MemEncodeError, WordBufError};
use crate::traits::*;
use crate::types::*;
use crate::utils::non_primitive::{drain_from, drain_into, mem_encode_required_capacity};
use crate::word_buf::WordBuf;

#[derive(Zeroize, Eq, PartialEq)]
enum TestBreakerBehaviour {
    FailAtRequiredCapacity,
    FailAtCodeInto,
    FailAtDecodeFrom,
}

#[derive(Zeroize)]
struct TestBreaker {
    behaviour: TestBreakerBehaviour,
    pub fixed_array: [u8; 64],
}

impl TestBreaker {
    pub fn new(behaviour: TestBreakerBehaviour) -> Self {
        Self {
            behaviour,
            fixed_array: [u8::MAX; 64],
        }
    }
}

impl MemDrainEncode for TestBreaker {
    fn mem_encode_required_capacity(&self) -> usize {
        if self.behaviour == TestBreakerBehaviour::FailAtRequiredCapacity {
            return usize::MAX;
        }

        return 1;
    }

    fn drain_into(&mut self, _words: &mut WordBuf) -> Result<(), MemEncodeError> {
        if self.behaviour == TestBreakerBehaviour::FailAtCodeInto {
            return Err(MemEncodeError::TestBreakerIntentionalEncodeError);
        }

        Ok(())
    }
}

impl MemDrainDecode for TestBreaker {
    fn drain_from(&mut self, _code: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        if self.behaviour == TestBreakerBehaviour::FailAtDecodeFrom {
            return Err(MemDecodeError::TestBreakerIntentionalDecodeError);
        }

        Ok(())
    }
}

#[test]
fn test_required_capacity() {
    let array_1: [MemCodeUnit; 0] = [];
    let array_2 = [MemCodeUnit::cast(1); 1];
    let array_3 = [MemCodeUnit::cast(2); 2];

    let fields_1: Vec<&dyn MemDrainEncode> = vec![&array_1];
    let fields_2: Vec<&dyn MemDrainEncode> = vec![&array_1, &array_2];
    let fields_3: Vec<&dyn MemDrainEncode> = vec![&array_1, &array_2, &array_3];

    let requirerd_capacity_1 = mem_encode_required_capacity(&fields_1);
    let requirerd_capacity_2 = mem_encode_required_capacity(&fields_2);
    let requirerd_capacity_3 = mem_encode_required_capacity(&fields_3);

    assert_eq!(requirerd_capacity_1, 2);
    assert_eq!(requirerd_capacity_2, 4);
    assert_eq!(requirerd_capacity_3, 7);
}

#[test]
fn test_drain_into_fails_reports_coertion_error() {
    let mut breaker = TestBreaker::new(TestBreakerBehaviour::FailAtRequiredCapacity);
    let mut fields: Vec<&mut dyn ZeroizableMemDrainEncode> = vec![&mut breaker];

    let mut wb = WordBuf::new(20);
    let result = drain_into(&mut fields, &mut wb);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::CoerceError(CoerceError::OutOfRange { .. }))
    ));

    // Assert zeroization!
    assert!(breaker.fixed_array.iter().all(|&b| b == 0));
    assert!(wb.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_drain_into_fails_to_push_required_capacity() {
    let mut array_1: [MemCodeUnit; 0] = [];
    let mut array_2 = [MemCodeUnit::cast(1); 1];
    let mut array_3 = [MemCodeUnit::cast(2); 2];

    let mut fields: Vec<&mut dyn ZeroizableMemDrainEncode> =
        vec![&mut array_1, &mut array_2, &mut array_3];

    let mut wb = WordBuf::new(0);
    let result = drain_into(fields.as_mut_slice(), &mut wb);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::WordBufError(
            WordBufError::CapacityExceededError
        ))
    ));

    // Assert zeroization!
    assert!(array_1.iter().all(|&b| b == 0));
    assert!(array_2.iter().all(|&b| b == 0));
    assert!(array_3.iter().all(|&b| b == 0));
    assert!(wb.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_drain_into_reports_error_from_decoding_fields() {
    let mut breaker = TestBreaker::new(TestBreakerBehaviour::FailAtCodeInto);
    let mut fields: Vec<&mut dyn ZeroizableMemDrainEncode> = vec![&mut breaker];

    let mut wb = WordBuf::new(3);
    let result = drain_into(&mut fields, &mut wb);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::TestBreakerIntentionalEncodeError)
    ));

    // Assert zeroization!
    assert!(breaker.fixed_array.iter().all(|&b| b == 0));
    assert!(wb.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_drain_into_ok() {
    let mut array_1: [MemCodeUnit; 0] = [];
    let mut array_2 = [MemCodeUnit::cast(1); 1];
    let mut array_3 = [MemCodeUnit::cast(2); 2];

    let fields: Vec<&dyn MemDrainEncode> = vec![&array_1, &array_2, &array_3];
    let required_capacity = mem_encode_required_capacity(&fields);

    let mut fields: Vec<&mut dyn ZeroizableMemDrainEncode> =
        vec![&mut array_1, &mut array_2, &mut array_3];

    let mut wb = WordBuf::new(required_capacity);
    let result = drain_into(fields.as_mut_slice(), &mut wb);

    assert!(result.is_ok());

    let buf_snapshot = format!("{:?}", wb.as_slice());
    assert_snapshot!(buf_snapshot);

    // Assert zeroization!
    assert!(array_1.iter().all(|&b| b == 0));
    assert!(array_2.iter().all(|&b| b == 0));
    assert!(array_3.iter().all(|&b| b == 0));
}

#[test]
fn test_try_drain_from_reports_invalid_preconditions() {
    let mut array_1 = [];
    let mut array_2 = [MemCodeUnit::cast(1); 1];
    let mut array_3 = [MemCodeUnit::cast(2); 2];

    let mut fields: Vec<&mut dyn ZeroizableMemDrainDecode> =
        vec![&mut array_1, &mut array_2, &mut array_3];

    let mut src = [];
    let result = drain_from(&mut fields, &mut src);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
    assert!(array_1.iter().all(|&b| b == 0));
    assert!(array_2.iter().all(|&b| b == 0));
    assert!(array_3.iter().all(|&b| b == 0));
}

#[test]
fn test_drain_from_reports_error_from_decoding_fields() {
    let mut breaker = TestBreaker::new(TestBreakerBehaviour::FailAtDecodeFrom);
    let mut fields: Vec<&mut dyn ZeroizableMemDrainDecode> = vec![&mut breaker];

    let mut src = [2, 1, 1];
    let result = drain_from(&mut fields, &mut src);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::TestBreakerIntentionalDecodeError)
    ));

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
    assert!(breaker.fixed_array.iter().all(|&b| b == 0));
}

#[test]
fn test_drain_from_ok() {
    let mut array_1 = [MemCodeUnit::default_zero_value(); 2];
    let mut fields: Vec<&mut dyn ZeroizableMemDrainDecode> = vec![&mut array_1];

    let mut src = [3, 2, 1, 1];
    let result = drain_from(&mut fields, &mut src);

    assert!(result.is_ok());
    assert_eq!(array_1, [1, 1]);

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
}

// This test ensures that *all* fields are properly zeroized
// when an encoding operation fails.
//
// It intentionally triggers a controlled failure using the
// `TestBreaker` to simulate an encode error and verify that
// both the encoder and its working buffer are securely wiped.
//
// Note:
// Although this test closely mirrors the one above, it is
// intentionally kept separate to make the failure and
// zeroization paths explicit and self-documenting.
#[test]
fn test_drain_into_zeroizes_all_fields_on_error() {
    let mut breaker = TestBreaker::new(TestBreakerBehaviour::FailAtCodeInto);
    let mut fields: Vec<&mut dyn ZeroizableMemDrainEncode> = vec![&mut breaker];

    // Intentionally fail due to insufficient buffer capacity.
    let mut wb = WordBuf::new(3);
    let result = drain_into(&mut fields, &mut wb);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::TestBreakerIntentionalEncodeError)
    ));

    // Assert zeroization!
    assert!(breaker.fixed_array.iter().all(|&b| b == 0));
    assert!(wb.as_slice().iter().all(|&b| b == 0));
}
