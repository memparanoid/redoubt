// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a container leaves behind once it has been filled and let go.
//!
//! # Two tests for every claim
//!
//! An absence on its own says nothing: a sweep that reaches nowhere reports a
//! clean process, and so does a container that wiped everything. So each
//! section here opens with the same operation run against a container that is
//! never let go, and that one has to be **found**. Whatever the rest of the
//! section reports is worth exactly as much as that.
//!
//! Each pair stands on its own. A control somewhere else in the file would say
//! that the sweep reaches *something*, which is not the question: what has to
//! be reachable is where **this** container puts its bytes.
//!
//! # Why size is an axis, and why each size is its own test
//!
//! A container that leaks a secret of thirty-two bytes and not one of thirty
//! kilobytes would be a strange thing. The other way round is not strange at
//! all: a large buffer is reallocated on the way up, is copied through a
//! routine that takes a different path by length, and puts enough pressure on
//! the register allocator that the compiler starts spilling to stack slots
//! nobody clears.
//!
//! One test per size rather than a loop inside one, because the sweep reads
//! the whole process: a size that leaks leaves the secret in memory, and every
//! size measured after it in the same process finds that copy and is blamed
//! for it. Under `nextest` each test is a process of its own, so the size that
//! failed is the name of the test that failed.
//!
//! # What goes inside the block
//!
//! ```text
//! let mut source = vec![0_u8; 32];
//! giving(&mut source);                    // the test's own doing, outside
//!
//! forensics!({
//!     let mut held = RedoubtVec::new();   // everything the crate does,
//!     capture(|| held.replace_from_mut_slice(&mut source));
//!     drop(held);                         // and the drop once it is frozen
//! });
//!
//! let report_after = watch.snapshot()?;
//! ```
//!
//! Everything this crate does is inside, from the container being made to it
//! being let go. What stays outside is the fixture: the bytes the test itself
//! put somewhere, which the test answers for and the crate does not.
//!
//! # Why the drop comes after the capture
//!
//! `capture` freezes the registers and the stack — everything the operation
//! left, copied out before anything can write over it.
//! It does not read the heap, and does not have to: the photograph reads that
//! live, later.
//!
//! Every container here keeps its bytes on the heap, behind a `Box` or a
//! `Vec`. So the copy a container is legitimately holding is not in what the
//! capture froze, and that is what lets the drop come afterwards: it empties
//! the allocation before the photograph and touches nothing the capture
//! already took. An absence can then only be residue the operation left.
//!
//! # What an absence here is contingent on
//!
//! The indirection, and not the instrument. Take the `Box` out of
//! `RedoubtArray` so the bytes live in the struct — a stack local, copied into
//! every slot it is moved out of, with nothing left to empty them — and every
//! absence in its sections turns red with the whole secret surfacing, while
//! every presence stays green.
//!
//! That is what these tests are reading. A container that stops holding its
//! bytes behind a pointer stops passing, which is the whole point of measuring
//! rather than arguing.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the secret could be. `nextest`, not `cargo test`.

#![cfg(target_os = "linux")]

mod support;

mod allocked_vec;
mod redoubt_array;
mod redoubt_option;
mod redoubt_string;
mod redoubt_vec;
