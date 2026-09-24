// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What opening the master key leaves behind.
//!
//! The needle is the key itself, opened once and turned around where it lies.
//! What is held from then on is the key backwards, which is not the key — and
//! that first open is the one contamination in here.
//!
//! # Why a difference is not enough
//!
//! Subtracting two photographs does not make that contamination go away. A
//! residue that vanishes while another appears reads as no change at all, and
//! so does a leak that lands exactly where the last one was overwritten. The
//! difference says what an operation *moved*, which is not the same as what is
//! there.
//!
//! So every photograph is also held to an absolute bound — [`QUIET`], the
//! widest run memory throws up by accident — and the first one is held to it
//! before anything has been opened at all. That one owes nothing to any other
//! photograph, and it is what makes the differences below worth reading.
//!
//! # One claim per test
//!
//! The control that says the sweep reaches the key plants a copy of it, and a
//! copy planted in a process is in every photograph that process takes
//! afterwards. Kept in the same test as a measurement, it can only come last —
//! after everything it was meant to vouch for had already been measured.
//!
//! Under `nextest` each test is a process of its own, so it does not have to:
//! the control is its own test, plants its copy in nobody else's memory, and
//! is read first.
//!
//! # What it caught
//!
//! `copy_from_slice` is `core::ptr::copy_nonoverlapping` underneath, and over
//! a runtime length that is a call into the C library's `memcpy`. glibc's
//! leaves the whole key in `zmm16` and `zmm17` — registers no form of
//! `vzeroall` reaches and compiled code never writes. On this instrument a
//! single open scored 222 with a run of all thirty-two bytes and the whole key
//! surfacing. The copy that replaced it scores nothing.
//!
//! So the assertions below are the shape of a regression that already
//! happened once.
//!
//! [`QUIET`]: redoubt_forensics::QUIET

#![cfg(target_os = "linux")]

mod master_key;
