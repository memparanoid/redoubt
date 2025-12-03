// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{FastZeroizable, ZeroizationProbe};

use crate::allocked_vec::AllockedVecBehaviour;

#[test]
fn test_allocked_vec_behaviour() {
    let mut behaviour = AllockedVecBehaviour::FailAtDrainFrom;

    assert!(!behaviour.is_zeroized());

    behaviour.fast_zeroize();

    assert!(behaviour.is_zeroized());
    assert!(matches!(behaviour, AllockedVecBehaviour::None));
}
