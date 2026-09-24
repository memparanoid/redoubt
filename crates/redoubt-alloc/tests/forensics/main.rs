// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the containers leave behind once they have been filled and let go.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.
//!
//! # What an absence here is contingent on
//!
//! The indirection, and not the instrument. Take the `Box` out of
//! `RedoubtArray` so the bytes live in the struct, and every absence in its
//! sections turns red with the whole secret surfacing, while every presence
//! stays green.

#![cfg(target_os = "linux")]

mod support;

mod allocked_vec;
mod redoubt_array;
mod redoubt_option;
mod redoubt_string;
mod redoubt_vec;
