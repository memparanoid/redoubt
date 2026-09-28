// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(all(target_os = "linux", hex_asm))]
mod forensics;

#[cfg(feature = "constant-time")]
mod constant_time;

mod backend;
mod decode;
mod encode;
mod roundtrip;
