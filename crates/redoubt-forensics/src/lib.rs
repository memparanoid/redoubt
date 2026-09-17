// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What is left of a secret in a process once it has been handed over.
//!
//! # The shape of the question
//!
//! Asking "are these bytes somewhere" means holding them, and holding them
//! makes the answer at least one. So the copy in hand is reversed in place,
//! which leaves the original nowhere, and the search reads that copy backwards
//! to look for it. Nothing has to be written down to be searched for, and a
//! count of zero is the claim that the value is in no second place.
//!
//! A count of zero on its own says nothing, so each one is worth exactly the
//! two that make it mean something: that the sweep reaches where the value
//! lives, and that the reversed search finds a copy when there is one to find.
//! Both are asserted in this crate's own tests, and a caller asserting an
//! absence owes the same pair.
//!
//! # Whether, and how much
//!
//! [`occurrences_reversed`] answers whether the secret is somewhere, and that
//! is the wrong question for what a copy leaves. Bytes move in the widths the
//! machine has, so what survives an operation is usually a piece: half of it in
//! a spill slot, a quarter in a scratch buffer nobody named. No search for the
//! whole thing finds any of that, and the zero it returns is true and useless.
//!
//! [`Forensics::snapshot_reversed`] asks the other question. It weighs every
//! unbroken run of the secret by how wide it is against how much memory it was
//! found in, and returns one number. One number is unreadable on its own, so
//! the reading is a difference: a photograph, the operation, another
//! photograph, and [`Report::against`].
//!
//! # Nobody's memory is read here
//!
//! An instrument that allocates while it measures is measuring itself, and one
//! fork only fixes half of that. So there are three processes: this one, an
//! analyst it forks, and the photograph the analyst forks. Every byte of the
//! subject's memory goes through the analyst, and the analyst does not come
//! back. What crosses into this process is five numbers.
//!
//! Where nothing may trace anything — a container without the capability, a
//! kernel locked down — there is no photograph and the analysis says so.
//!
//! # What it does not cover
//!
//! A value that lived only in registers. Those never reach a mapping to be read
//! out of, and a sweep that finds nothing has not looked there.
//!
//! # What it does cover, and would not in general
//!
//! History. A copy in a page the allocator has already handed back to the
//! kernel is out of reach of any sweep — but a buffer small enough is served
//! out of the heap rather than a mapping of its own, so freeing it unmaps
//! nothing and the page it sat in is still read. That is what makes a zero a
//! statement about what was and not only about what is, and it stops holding
//! for anything large enough to be given its own mapping.
//!
//! # A process each
//!
//! The memory being read is the whole process's, so a test sharing it is
//! another place the value could be and another test's needle to trip over.
//! `nextest`, not `cargo test`.

#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
mod analysis;

#[cfg(target_os = "linux")]
mod errors;

#[cfg(target_os = "linux")]
mod forensics;

#[cfg(target_os = "linux")]
mod macros;

#[cfg(target_os = "linux")]
mod spiller;

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

// What `capture!` expands into reaches by name, and nothing else has a use for
// any of it: the room's address, the entry that writes the vectors alone, and
// the three numbers the window is made of.
#[cfg(target_os = "linux")]
pub use spiller::{SPILL, redoubt_spill_room, redoubt_spill_vectors};

#[cfg(target_os = "linux")]
pub use window::{COPY, FLOOR, SP, open};
