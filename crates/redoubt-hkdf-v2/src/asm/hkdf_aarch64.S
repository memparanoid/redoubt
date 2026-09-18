// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// HKDF-SHA256 by hand, for aarch64 under AAPCS.
//
// # The baseline, and nothing above it
//
// Every instruction here is in the ARMv8-A baseline. There is no runtime
// feature detection, no cryptographic-extension path and no SVE path: what the
// machine has is not asked, so the same instructions run everywhere and what is
// written here is what executed. A vectorized second copy would need a check, a
// third copy of the rounds, and a wipe written once per register file — and
// none of that is paid for until somebody measures that it matters.
//
// # What crosses the boundary
//
// Four routines, in the order `backend/mod.rs` declares them. Every argument is
// a pointer to storage the caller declared, except the lengths, which are
// public: how long a message is says nothing about what is in it. Nothing is
// returned — a returned value leaves in a register, and a register carrying the
// answer out is one the wipe at the end cannot touch.
//
// # What must not branch on a secret
//
// Nothing here does. SHA-256 is adds, rotations and boolean functions over
// words, and the only branches are the block loop and the padding, which are
// decided by lengths the caller already knows.
//
// # What this file cannot answer for
//
// A core dump, a page that went to swap, a debugger attached to the process, or
// a signal handler that ran between two of these instructions. The registers
// and the frame are emptied before each routine returns; what the kernel did
// with them in between is outside what any of this can promise.

// ============================================================================
// Nothing here yet
// ============================================================================
//
// The routines are written against the Rust in `backend/rust/`, which is what
// answers today. Until they land, `backend/asm.rs` forwards to that Rust and
// this file is what the build script compiles so the seam and its `cfg` are
// exercised from the start rather than wired up at the end.

    .section .note.GNU-stack,"",@progbits
