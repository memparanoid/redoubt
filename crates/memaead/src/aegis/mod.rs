// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS family of authenticated encryption algorithms.
//!
//! Based on draft-irtf-cfrg-aegis-aead-18.

pub mod intrinsics;
pub mod aegis128l;

pub use aegis128l::Aegis128L;
