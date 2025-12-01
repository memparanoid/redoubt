// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::utils::test_all_pairs;

#[test]
fn test_bool_all_pairs() {
    let set = [true, false];
    test_all_pairs(&set);
}
