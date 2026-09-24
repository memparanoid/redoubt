// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the codec leaves behind, measured one function at a time.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

mod support;

mod blankets;
mod codec_buffer;
mod collections;
mod decode_buffer;
mod primitives;
