// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The one value a construction may branch on after it was derived from a
//! secret: the answer it hands back.

/// `answer`, told to Memcheck as public when the `constant-time` run is
/// measuring, and handed back unchanged in every build.
///
/// A tag either matches or not, and the caller learns which from what comes
/// back; branching on it inside the construction says nothing the caller will
/// not know. Handed back rather than marked in place: a copy the compiler kept
/// in a register would still read as secret.
#[inline(always)]
#[must_use]
pub fn declassify(answer: bool) -> bool {
    #[cfg(all(feature = "constant-time", target_os = "linux", target_env = "gnu"))]
    {
        let held = answer;

        let _ = crabgrind::memcheck::mark_memory(
            (&raw const held).cast(),
            core::mem::size_of::<bool>(),
            crabgrind::memcheck::MemState::Defined,
        );

        // SAFETY: `held` is a live local of this frame, read as the type it is.
        unsafe { core::ptr::read_volatile(&raw const held) }
    }

    #[cfg(not(all(feature = "constant-time", target_os = "linux", target_env = "gnu")))]
    {
        answer
    }
}
