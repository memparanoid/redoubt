// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the two halves of a cipherbox leave behind.
//!
//! # The last layer without one
//!
//! Everything underneath has been measured and leaves nothing: the copy at
//! every size it has a path for, `RedoubtVec` replaced and extended, the
//! option, `mem::take`, the codec in both directions, and AEGIS in both
//! directions. A box built out of those leaves the secret in plain sight once
//! it is large enough, so whatever is left is here.
//!
//! One field, one size at a time, and the two halves apart — `encrypt_struct`
//! and `decrypt_struct` rather than `open` and its five relatives. If one of
//! them is the answer, this says which.

use redoubt_alloc::RedoubtVec;
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_vault::{cipherbox, leak_master_key};
use redoubt_zero::{FastZeroizable, RedoubtZero};

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Every size worth asking about. The box above was clean at one copy of the
/// secret and left it in plain sight by four.
const SIZES: [usize; 8] = [32, 64, 128, 256, 512, 1024, 4096, 32768];

/// How much of the master key the box takes.
const WIDE: usize = 16;

#[cipherbox(OneFieldBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct OneField {
    all_of_it: RedoubtVec<u8>,
}

/// The needle, built from its last byte to its first.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The secret over and over, by the copy that erases what it used, so that
/// filling the source is not itself the leak.
fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// A value of that many bytes of the secret, filled the clean way.
fn value(of: usize) -> OneField {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    let mut it = OneField::default();

    it.all_of_it.replace_from_mut_slice(&mut source);

    it
}

/// Everything a caller must be able to say about what an operation left, at
/// every size.
fn leaves_nothing_at_any_size(
    what: &str,
    mut work: impl FnMut(&mut OneFieldBox, &[u8], usize) -> Result<(), AnyError>,
) -> Result<(), AnyError> {
    // Opened once and turned around where it lies, so what is held from here
    // on is not the key. Built before the first photograph, like everything
    // else that is not what is being asked about.
    let mut box_ = OneFieldBox::new();
    let key = leak_master_key(WIDE).expect("no master key").to_vec();

    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing in the box yet");

    for of in SIZES {
        let report_after = forensics!(watch, { work(&mut box_, &key, of) });

        report_after.summary_against(&report_before, &format!("{what}, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived {what} of {of} bytes: {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived {what} of {of} bytes, and {QUIET} is what \
             memory has by accident: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "{what} of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    drop(core::hint::black_box((box_, key)));

    Ok(())
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the secret when the secret is plainly there.
#[test]
fn test_the_sweep_finds_the_secret_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = vec![0_u8; SECRET.len()];

    giving(&mut held);
    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the secret, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where a copy lives, so every absence this file \
         reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box(held));

    Ok(())
}

// ============================================================================
// CipherBox::encrypt_struct
// ============================================================================

/// The way in, on its own: a value built outside, encrypted, and cleared.
#[test]
fn test_encrypt_struct_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("encrypted", |box_, key, of| {
        let mut it = value(of);

        box_.inner.encrypt_struct(key, &mut it)?;

        it.fast_zeroize();

        drop(core::hint::black_box(it));

        Ok(())
    })
}

// ============================================================================
// CipherBox::decrypt_struct
// ============================================================================

/// And the way out, which is where the plaintext reappears — in the field, in
/// the buffer it was decrypted from, and in whatever the decoder read it
/// through.
#[test]
fn test_decrypt_struct_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("decrypted", |box_, key, of| {
        let mut it = value(of);

        box_.inner.encrypt_struct(key, &mut it)?;
        it.fast_zeroize();

        let back = box_.inner.decrypt_struct(key)?;

        drop(core::hint::black_box((back, it)));

        Ok(())
    })
}
