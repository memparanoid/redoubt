// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_alloc::RedoubtVec;
use redoubt_buffer::BufferError;
use redoubt_forensics::{AnyError, Forensics, QUIET, Report};

use crate::master_key::leak_master_key;

use needles::{SECRET, backwards, master_key_backwards, master_key_width};

/// The needles an operation of a box is held to, the secret and the master key,
/// each with its photograph from before.
pub(crate) struct Watching {
    pub(crate) secret: Forensics,
    secret_before: Report,
    pub(crate) key: Forensics,
    key_before: Report,
}

impl Watching {
    pub(crate) fn start() -> Result<Self, AnyError> {
        let mut secret = Forensics::watching(&backwards())?;
        let mut key = Forensics::watching(&master_key_backwards()?)?;

        let secret_before = secret.snapshot()?;
        let key_before = key.snapshot()?;

        Ok(Self {
            secret,
            secret_before,
            key,
            key_before,
        })
    }

    /// Asserts neither needle survived.
    pub(crate) fn none_left(&mut self, before: &str, what: &str) -> Result<(), AnyError> {
        let secret_after = self.secret.snapshot()?;
        let key_after = self.key.snapshot()?;

        leaves_nothing(&self.secret_before, before, &secret_after, what);
        leaves_nothing(
            &self.key_before,
            before,
            &key_after,
            &format!("{what}, in the master key"),
        );

        Ok(())
    }
}

/// Writes the secret over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// A field holding the secret.
pub(crate) fn a_field() -> RedoubtVec<u8> {
    let mut source = vec![0_u8; 32];

    giving(&mut source);

    let mut field = RedoubtVec::default();

    field.replace_from_mut_slice(&mut source);

    field
}

/// A copy of the key a box encrypts with, made by the copy that erases what it
/// used: `to_vec` would be the C library's `memcpy`.
pub(crate) fn a_key() -> Result<Vec<u8>, AnyError> {
    let opened = leak_master_key(master_key_width())?;
    let mut key = vec![0_u8; opened.len()];

    // SAFETY: `key` was made as long as `opened`, and the two are different
    // allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(opened.as_ptr(), key.as_mut_ptr(), key.len()) };

    Ok(key)
}

/// A callback that copies what it is handed into `into`, through the copy that
/// erases what it used.
pub(crate) fn copying_into(into: &mut [u8]) -> impl FnMut(&[u8]) -> Result<(), BufferError> + '_ {
    move |key| {
        let len = into.len().min(key.len());

        // SAFETY: `len` fits both, and the key's page and `into` are different
        // allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(key.as_ptr(), into.as_mut_ptr(), len) };

        Ok(())
    }
}

/// Asserts the secret was found. Without a presence, an absence cannot be told
/// apart from a sweep that reaches nowhere.
pub(crate) fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// Asserts the secret is gone: not whole, no run past `QUIET`, and a score that
/// did not move. Each alone passes a process that kept part of it.
pub(crate) fn leaves_nothing(
    report_before: &Report,
    before: &str,
    report_after: &Report,
    what: &str,
) {
    println!();
    report_before.summary(before);
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret was left behind by {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes of the secret was left behind by {what}, and {QUIET} \
         is what memory has by accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(
        delta.is_noise(),
        "{what} moved the score past chance: {delta}"
    );
}
