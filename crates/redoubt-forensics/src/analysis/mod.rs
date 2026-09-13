// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Reading another process's memory, and weighing what is in it.
//!
//! Three layers, and they only point one way:
//!
//! - [`state`] is the block — one allocation, reserved before anything
//!   happens, laid out so that nothing below has to allocate.
//! - [`memory`] is the three processes and the sweep: what a photograph is,
//!   how it is frozen, and how every writable byte of it is walked.
//! - [`score`] is arithmetic over those bytes. It forks nothing and allocates
//!   nothing, and can be read without a process to look at.
//! - [`report`] is what comes out.
//!
//! [`crate::Forensics`] sits on top of all four and is the only thing that
//! puts them together.

pub(crate) mod memory;
pub(crate) mod report;
pub(crate) mod score;
pub(crate) mod state;
