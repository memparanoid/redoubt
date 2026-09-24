// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{AnyError, QUIET, Report};
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;

use needles::SECRET;

/// Writes the secret over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// `of` bytes of the secret, over and over.
pub(crate) fn secret_bytes(of: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; of];

    giving(&mut bytes);

    bytes
}

/// A buffer holding thirty-two bytes of the secret.
pub(crate) fn a_buffer_holding() -> Result<RedoubtCodecBuffer, AnyError> {
    let mut source = secret_bytes(32);
    let mut buffer = RedoubtCodecBuffer::with_capacity(32);

    buffer.write_slice(&mut source)?;

    source.fast_zeroize();

    Ok(buffer)
}

/// Sixteen bytes of the secret in a `u128`, the widest primitive.
pub(crate) fn a_u128() -> Box<u128> {
    let mut value = Box::new(0_u128);

    giving(bytes_of(&mut *value));

    value
}

/// Thirty-two bytes of the secret in two `u128`s, the whole needle.
pub(crate) fn two_u128() -> Box<[u128; 2]> {
    let mut values = Box::new([0_u128; 2]);

    giving(bytes_of(&mut *values));

    values
}

fn bytes_of<T: Copy>(value: &mut T) -> &mut [u8] {
    // SAFETY: only called with `u128` and arrays of it, which have no padding
    // and a value for every bit pattern, and the borrow is exclusive.
    unsafe {
        core::slice::from_raw_parts_mut(value as *mut T as *mut u8, core::mem::size_of::<T>())
    }
}

/// Takes the value by move and drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value by move and never drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
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
