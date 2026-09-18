// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Which of the two a caller gets without asking.

use crate::Backend;

// ============================================================================
// impl Default for Backend
// ============================================================================

/// What ships takes the assembly, and nothing above says so.
///
/// Every constructor in the workspace resolves this, and none of them names it.
/// The day it answers `Rust` the whole of it runs the portable path — and no
/// test anywhere goes red, because the two backends compute the same numbers.
/// That is the one thing about this type that can be wrong quietly.
#[test]
fn test_default_asks_for_whatever_the_target_has() {
    assert_eq!(Backend::default(), Backend::Auto);
}
