// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for mocking entropy sources and nonce generators.
//!
//! Provides mock implementations with configurable behavior for testing.

mod mock_entropy_source;
mod mock_nonce_session_generator;

pub use mock_entropy_source::{MockEntropySource, MockEntropySourceBehaviour};
pub use mock_nonce_session_generator::{
    MockNonceSessionGenerator, MockNonceSessionGeneratorBehaviour,
};
