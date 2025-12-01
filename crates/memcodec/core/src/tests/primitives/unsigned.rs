// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::utils::{equidistant_unsigned, test_all_pairs, EQUIDISTANT_SAMPLE_SIZE};

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
