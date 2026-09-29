// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The instrument behind `redoubt-forensics`.

#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
mod analysis;

#[cfg(target_os = "linux")]
mod errors;

#[cfg(target_os = "linux")]
mod forensics;

#[cfg(target_os = "linux")]
mod frame;

#[cfg(target_os = "linux")]
mod macros;

#[cfg(target_os = "linux")]
mod spiller;

#[cfg(target_os = "linux")]
mod verdicts;

#[cfg(target_os = "linux")]
mod watching;

#[cfg(target_os = "linux")]
mod window;

// The whole of it. Everything else — the block, the three processes, the
// weighing — is reachable only through these, and a caller that needed one of
// them directly would be doing something this crate has not thought about.
#[cfg(target_os = "linux")]
pub use analysis::report::{Change, QUIET, Report};

#[cfg(target_os = "linux")]
pub use errors::{AnyError, Reason};

#[cfg(target_os = "linux")]
pub use forensics::{Forensics, occurrences, occurrences_reversed};

#[cfg(target_os = "linux")]
pub use frame::capture;

#[cfg(target_os = "linux")]
pub use spiller::pick_spiller;

// What `freeze!` expands into reaches by name, and nothing else has a use for
// any of it: the room's address, the entry that writes the vectors alone, and
// the numbers the window is made of.
#[cfg(target_os = "linux")]
pub use spiller::{SPILL, redoubt_spill_room, redoubt_spill_vectors};

#[cfg(target_os = "linux")]
pub use verdicts::{is_found, leaves_no_copy, leaves_nothing};

#[cfg(target_os = "linux")]
pub use watching::Watching;

#[cfg(target_os = "linux")]
pub use window::{COPY, FLOOR, SP, TOP, open};
