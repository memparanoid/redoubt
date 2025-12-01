// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};

use super::utils::test_collection_varying_capacities;

#[test]
fn test_vec_test_breaker_varying_capacities() {
    let set: Vec<TestBreaker> = (0..250)
        .map(|i| TestBreaker::new(TestBreakerBehaviour::None, i))
        .collect();

    test_collection_varying_capacities(
        &set,
        |cap| Vec::with_capacity(cap),
        |vec, slice| {
            vec.clear();
            vec.extend_from_slice(slice);
        },
        |a, b| a == b,
    );
}
