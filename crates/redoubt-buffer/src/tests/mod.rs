// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod page;
mod portable_buffer;

#[cfg(unix)]
mod page_buffer;
#[cfg(target_os = "linux")]
mod utils;
