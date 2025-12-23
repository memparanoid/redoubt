// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test proxies that route to either ASM or Rust implementations
//! based on feature flags and platform support

pub mod hmac;
pub mod sha256;
