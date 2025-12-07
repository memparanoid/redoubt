// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::zeroize::{zeroize_64, zeroize_128};

#[test]
fn test_zeroize_64() {
    let mut buf = [0xFFu8; 64];
    zeroize_64(&mut buf);
    assert!(buf.iter().all(|&b| b == 0), "zeroize_64 failed to zero buffer");
}

#[test]
fn test_zeroize_128() {
    let mut buf = [0xFFu8; 128];
    zeroize_128(&mut buf);
    assert!(buf.iter().all(|&b| b == 0), "zeroize_128 failed to zero buffer");
}
