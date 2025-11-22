// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::utils::is_vec_fully_zeroized;

#[test]
fn test_is_vec_fully_zeroized() {
    let mut vec = vec![1u8, 2, 3, 4, 5];

    vec.truncate(2);

    for byte in vec.iter_mut() {
        *byte = 0;
    }

    assert!(!is_vec_fully_zeroized(&vec));

    vec.zeroize();

    assert!(is_vec_fully_zeroized(&vec));
}
