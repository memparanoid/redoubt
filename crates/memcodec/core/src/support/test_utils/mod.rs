// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod permute;
mod test_breaker;
mod utils;

pub use permute::{apply_permutation, index_permutations};
pub use test_breaker::{TestBreaker, TestBreakerBehaviour};
pub use utils::tamper_encoded_bytes_for_tests;
