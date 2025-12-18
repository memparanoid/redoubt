// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(all(
    any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", not(target_os = "windows"))
    ),
    not(target_os = "wasi")
))]
mod aegis128l;
mod xchacha20poly1305;
