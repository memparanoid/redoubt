// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod support;

#[cfg(all(target_os = "linux", aegis128l_asm))]
mod forensics;

mod aegis128l;
mod libaegis;
mod probes;
mod rfc;
mod wycheproof;
