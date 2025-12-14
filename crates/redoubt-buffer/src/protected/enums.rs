// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Enums for ProtectedBuffer configuration and internal state

/// Protection strategy for the buffer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProtectionStrategy {
    /// Full protection: mlock + mprotect toggling (PROT_NONE when idle)
    MemProtected,
    /// Partial protection: mlock only (no mprotect toggling)
    MemNonProtected,
}

/// Stages during buffer creation (used for testing with hooks).
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum TryCreateStage {
    Lock,
    Protect,
    FillWithPattern0,
}
