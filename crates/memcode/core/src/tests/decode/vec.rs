// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{traits::*, types::MemCodeUnit};

#[test]
fn test_vec_drain_from_ok_zeroizes_words() {
    let mut dst = vec![MemCodeUnit::cast(1)];
    let mut words = [4, 1, 2, 3, 4];

    let result = dst.drain_from(&mut words);

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(words.iter().all(|&b| b == 0));
}
