// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities re-exported from redoubt-aead and redoubt-codec

#[cfg(feature = "test-utils")]
pub use redoubt_aead::support::test_utils::*;
#[cfg(feature = "test-utils")]
pub use redoubt_codec::support::test_utils::*;
#[cfg(feature = "test-utils")]
pub use redoubt_rand::support::test_utils::*;
