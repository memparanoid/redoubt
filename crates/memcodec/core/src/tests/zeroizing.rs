// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{FastZeroizable, ZeroizationProbe};

use crate::zeroizing::Zeroizing;

#[test]
fn test_primitive_fast_zeroize() {
    let mut src = 20;
    let mut primitive = Zeroizing::from(&mut src);

    assert!(src.is_zeroized());

    primitive.fast_zeroize();

    assert!(primitive.is_zeroized());
}
