// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Shared test suite for AEGIS-128L backends.
//!
//! Includes Wycheproof conformance vectors and implementation-specific tests
//! for error paths common to both x86 and ARM assembly implementations.
//!
//! ## License
//!
//! GPL-3.0-only

#![warn(missing_docs)]

mod wycheproof;
mod wycheproof_vectors;

pub use wycheproof::{
    run_aegis128l_flipped_tag_tests, run_aegis128l_generate_nonce_test,
    run_aegis128l_invalid_size_decrypt_tests, run_aegis128l_invalid_size_encrypt_tests,
    run_aegis128l_roundtrip_tests, run_aegis128l_wycheproof_tests,
};
