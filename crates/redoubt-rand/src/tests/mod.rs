// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(target_os = "linux")]
mod forensics;

mod backend;
mod fill;
mod session;
mod support;
mod system;

#[cfg(target_os = "linux")]
mod utils;
