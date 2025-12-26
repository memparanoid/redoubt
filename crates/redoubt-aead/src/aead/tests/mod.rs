// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(all(feature = "asm", is_aegis_asm_eligible))]
mod aegis128l;
mod xchacha20poly1305;
