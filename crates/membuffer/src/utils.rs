// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub fn fill_with_pattern(slice: &mut [u8], pattern: u8) {
    for byte in slice.iter_mut() {
        *byte = pattern;
    }
}
