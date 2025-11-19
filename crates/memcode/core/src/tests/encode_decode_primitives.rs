// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{MemDecodeError, MemEncodeError, WordBufError};
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

fn encode_decode_roundtrip_ok<
    T: MemDrainEncode + MemDrainDecode + Default + Copy + Eq + core::fmt::Debug,
>(
    value: T,
) {
    let mut src = value;
    let mut buf = WordBuf::new(value.mem_encode_required_capacity());

    // Encode
    src.drain_into(&mut buf).expect("encode failed");
    assert_eq!(buf.len(), 2);

    // Decode
    let mut target = T::default();
    target
        .drain_from(buf.as_mut_slice())
        .expect("decode failed");

    assert_eq!(
        value,
        target,
        "roundtrip mismatch for {}",
        core::any::type_name::<T>()
    );

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
}

fn assert_decode_failure_with_zeroization<
    T: MemDrainEncode + MemDrainDecode + Default + Copy + Eq + core::fmt::Debug,
>(
    mut value: T,
) {
    let mut words = [1, MemCodeWord::MAX];
    let result = value.drain_from(&mut words);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::CoerceError(_))));

    // Assert zeroization!
    assert!(words.iter().all(|b| *b == 0));
}

// Helper: asserts encode error, source zeroization via f(&mut T), and buffer zeroized.
// with_capacity=true => buffer sized to required capacity (coerce path)
// with_capacity=false => zero-capacity buffer (capacity-exceeded path)
fn assert_encode_err_case<T, FExpect, FZero>(
    mut src: T,
    with_capacity: bool,
    expect_err: FExpect,
    zeroized: FZero,
) where
    T: MemDrainEncode + Default + PartialEq,
    FExpect: Fn(&MemEncodeError) -> bool,
    FZero: Fn(&mut T) -> bool,
{
    let mut buf = if with_capacity {
        WordBuf::new(src.mem_encode_required_capacity())
    } else {
        WordBuf::new(0)
    };

    let result = src.drain_into(&mut buf);
    assert!(result.is_err());

    let error = result.err().unwrap();
    assert!(expect_err(&error));

    // Assert zeroization of source via callback
    assert!(zeroized(&mut src));

    // Assert zeroization of buffer
    assert!(buf.as_slice().iter().all(|&w| w == 0));
}

#[test]
fn test_primitives_roundtrip_ok_zeroizes_wordbuf() {
    encode_decode_roundtrip_ok::<u8>(200);
    encode_decode_roundtrip_ok::<u16>(60_000);
    encode_decode_roundtrip_ok::<u32>(123_456);
    encode_decode_roundtrip_ok::<u64>(1_234_567);
    encode_decode_roundtrip_ok::<usize>(999_999);
    encode_decode_roundtrip_ok::<bool>(true);
    encode_decode_roundtrip_ok::<bool>(false);
}

#[test]
fn test_decode_failure_with_zeroization() {
    assert_decode_failure_with_zeroization::<u8>(u8::MAX);
    assert_decode_failure_with_zeroization::<u16>(u16::MAX);
}

#[test]
fn test_encode_err_zeroizes_wordbuf_and_source() {
    let is_capacity_exceeded_err = |e: &MemEncodeError| {
        matches!(
            e,
            MemEncodeError::WordBufError(WordBufError::CapacityExceededError)
        )
    };
    let is_coerce_err = |e: &MemEncodeError| matches!(e, MemEncodeError::CoerceError(_));

    // Capacity-exceeded path (with_capacity = false) for all types
    assert_encode_err_case::<u8, _, _>(u8::MAX, false, is_capacity_exceeded_err, |v: &mut u8| {
        *v == 0
    });
    assert_encode_err_case::<u16, _, _>(
        u16::MAX,
        false,
        is_capacity_exceeded_err,
        |v: &mut u16| *v == 0,
    );
    assert_encode_err_case::<u32, _, _>(
        u32::MAX,
        false,
        is_capacity_exceeded_err,
        |v: &mut u32| *v == 0,
    );
    assert_encode_err_case::<bool, _, _>(true, false, is_capacity_exceeded_err, |v: &mut bool| {
        *v == false
    });
    assert_encode_err_case::<bool, _, _>(false, false, is_capacity_exceeded_err, |v: &mut bool| {
        *v == false
    });

    // Coerce overflow path (with_capacity = true) for widths > u32
    assert_encode_err_case::<u64, _, _>(u64::MAX, true, is_coerce_err, |v: &mut u64| *v == 0);
    assert_encode_err_case::<usize, _, _>(usize::MAX, true, is_coerce_err, |v: &mut usize| *v == 0);
}

#[test]
fn test_precondition_violation_on_drain_from() {
    let mut x_u8: u8 = u8::MAX;
    let mut x_u16: u16 = u16::MAX;
    let mut x_u32: u32 = u32::MAX;
    let mut x_u64: u64 = u64::MAX;
    let mut x_usize: usize = usize::MAX;
    let mut bool_true = true;
    let mut bool_false = false;

    let result_x_u8 = x_u8.drain_from(&mut []);
    let result_x_u16 = x_u16.drain_from(&mut []);
    let result_x_u32 = x_u32.drain_from(&mut []);
    let result_x_u64 = x_u64.drain_from(&mut []);
    let result_x_usize = x_usize.drain_from(&mut []);
    let result_bool_true = bool_true.drain_from(&mut []);
    let result_bool_false = bool_false.drain_from(&mut []);

    assert!(matches!(
        result_x_u8,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_x_u16,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_x_u32,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_x_u64,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_x_usize,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_bool_true,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
    assert!(matches!(
        result_bool_false,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));

    // Assert zeroization!
    assert_eq!(x_u8, 0);
    assert_eq!(x_u16, 0);
    assert_eq!(x_u32, 0);
    assert_eq!(x_u64, 0);
    assert_eq!(x_usize, 0);
    assert_eq!(bool_true, false);
    assert_eq!(bool_false, false);
}
