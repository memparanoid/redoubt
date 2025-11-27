// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure buffer with locked capacity and automatic zeroization.
#[cfg(test)]
mod tests;

mod buffer;

pub use buffer::Buffer;
