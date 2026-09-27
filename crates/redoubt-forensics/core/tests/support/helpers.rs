// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The guard every test file here opens its tests with.

/// A test that needs a process to itself, or a word about why it did not run.
///
/// Silently passing would be worse than failing: the sweep reads the whole
/// process, so a secret one test holds on purpose is a secret another test's
/// absence is asserted against.
macro_rules! alone {
    () => {
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!("skipped: this test needs a process of its own. `cargo nextest run`.");

            return Ok(());
        }
    };
}

pub(crate) use alone;
