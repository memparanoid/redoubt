// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One file here for each file there, and the same shape of directory around
//! them.

mod support;

#[cfg(all(target_os = "linux", poly1305_asm))]
mod forensics;

mod backend;
mod rfc;
