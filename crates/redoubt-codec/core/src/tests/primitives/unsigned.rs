// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{DecodeBufferError, DecodeError};
use crate::traits::Decode;

use super::utils::{EQUIDISTANT_SAMPLE_SIZE, equidistant_unsigned, test_all_pairs};

#[test]
fn test_u8_all_pairs() {
    let set = equidistant_unsigned::<u8>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_u16_all_pairs() {
    let set = equidistant_unsigned::<u16>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_u32_all_pairs() {
    let set = equidistant_unsigned::<u32>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_u64_all_pairs() {
    let set = equidistant_unsigned::<u64>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_u128_all_pairs() {
    let set = equidistant_unsigned::<u128>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_usize_all_pairs() {
    #[cfg(target_pointer_width = "64")]
    let set: Vec<usize> = equidistant_unsigned::<u64>(EQUIDISTANT_SAMPLE_SIZE)
        .into_iter()
        .map(|x| x as usize)
        .collect();

    #[cfg(target_pointer_width = "32")]
    let set: Vec<usize> = equidistant_unsigned::<u32>(EQUIDISTANT_SAMPLE_SIZE)
        .into_iter()
        .map(|x| x as usize)
        .collect();

    test_all_pairs(&set);
}

// decode_from empty buffers

#[test]
fn test_unsigned_decode_from_empty_buffer() {
    macro_rules! test_type {
        ($ty:ty) => {{
            let mut value: $ty = 0;
            let mut empty_buf = &mut [][..];
            let result = value.decode_from(&mut empty_buf);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(DecodeError::DecodeBufferError(
                    DecodeBufferError::OutOfBounds
                ))
            ));
        }};
    }

    test_type!(u8);
    test_type!(u16);
    test_type!(u32);
    test_type!(u64);
    test_type!(u128);
    test_type!(usize);
}
