// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the assembly leaves behind, where there is assembly to ask.
//!
//! The gate is here and not on each test, so a target without the file, or an
//! architecture whose probe is not written yet, drops the whole of it rather
//! than a list of items each saying the same thing.

#![cfg(all(
    hkdf_asm,
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod probes;
