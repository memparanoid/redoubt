// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod array;
mod helpers;
mod slice;
mod vec;

// Re-export public helpers
pub use helpers::{
    drain_from, drain_into, mem_bytes_required, mem_decode_assert_num_elements,
    to_bytes_required_dyn_ref, to_decode_dyn_mut, to_encode_dyn_mut, to_zeroizable_dyn_mut,
};

// Re-export internal helpers (not public API, but needed within collections tests)
#[cfg(test)]
pub(crate) use helpers::extract_collection_header;
