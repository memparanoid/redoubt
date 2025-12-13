// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{DecodeBufferError, DecodeError};
use crate::traits::Decode;

use super::utils::{equidistant_signed, test_all_pairs, EQUIDISTANT_SAMPLE_SIZE};

#[test]
fn test_i8_all_pairs() {
    let set = equidistant_signed::<i8>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i16_all_pairs() {
    let set = equidistant_signed::<i16>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i32_all_pairs() {
    let set = equidistant_signed::<i32>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i64_all_pairs() {
    let set = equidistant_signed::<i64>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i128_all_pairs() {
    let set = equidistant_signed::<i128>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_isize_all_pairs() {
    #[cfg(target_pointer_width = "64")]
    let set: Vec<isize> = equidistant_signed::<i64>(EQUIDISTANT_SAMPLE_SIZE)
        .into_iter()
        .map(|x| x as isize)
        .collect();

    #[cfg(target_pointer_width = "32")]
    let set: Vec<isize> = equidistant_signed::<i32>(EQUIDISTANT_SAMPLE_SIZE)
        .into_iter()
        .map(|x| x as isize)
        .collect();

    test_all_pairs(&set);
}

// decode_from empty buffers

#[test]
fn test_signed_decode_from_empty_buffer() {
    macro_rules! test_type {
        ($ty:ty) => {{
            let mut value: $ty = 0;
            let mut empty_buf = &mut [][..];
            let result = value.decode_from(&mut empty_buf);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(DecodeError::DecodeBufferError(DecodeBufferError::OutOfBounds))
            ));
        }};
    }

    test_type!(i8);
    test_type!(i16);
    test_type!(i32);
    test_type!(i64);
    test_type!(i128);
    test_type!(isize);
}
