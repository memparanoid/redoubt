// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the buffers leave behind.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.
//!
//! # A page is out of the sweep's reach
//!
//! The sweep reads the mappings that are readable and writable at once. A page
//! buffer's page is `---p` while closed and `-w-p` while open, so a photograph
//! never sees what is inside it — which does not mean it is not in memory.
//! What is measured of a page buffer is what its operations leave in registers
//! and on the stack.

mod support;

mod page;
mod page_buffer;
mod portable_buffer;
