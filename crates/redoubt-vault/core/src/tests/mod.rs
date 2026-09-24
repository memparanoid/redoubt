// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(target_os = "linux")]
mod forensics;

mod cipherbox;
mod consts;
mod helpers;
mod master_key;
mod utils;
