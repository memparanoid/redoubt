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
//! One field, one size at a time, and the two halves apart —
//! `encrypt_struct` and `decrypt_struct` rather than `open` and its five
//! relatives. If one of them is the answer, this says which.
//!
//! # Two tests for every claim
//!
//! Each section opens with the same operation run against a value that is
//! never cleared, and that one has to be **found**. An absence is worth
//! exactly as much as the presence beside it: a sweep that reaches nowhere
//! reports a clean process, and so does a box that left nothing.
//!
//! # One size per test
//!
//! The sweep reads the whole process, so a size that leaks leaves the secret
//! in memory and every size measured after it in the same process finds that
//! copy and is blamed for it. Under `nextest` each test is a process of its
//! own, so the size that failed is the name of the test that failed.

use redoubt_alloc::RedoubtVec;
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, elenchos};
use redoubt_vault::{cipherbox, leak_master_key};
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::is_found;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// How much of the master key the box takes.
const WIDE: usize = 16;

#[cipherbox(OneFieldBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct OneField {
    all_of_it: RedoubtVec<u8>,
}

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
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

/// An empty box and the key it works with.
///
/// The key is opened once and what is held from here on is a copy of it, which
/// is not the needle. Built before the first photograph, like everything else
/// that is not what is being asked about.
fn a_box() -> Result<(OneFieldBox, Vec<u8>), AnyError> {
    let one_field_box = OneFieldBox::new();
    let key = leak_master_key(WIDE)?.to_vec();

    Ok((one_field_box, key))
}

/// The three things an absence has to survive.
///
/// The whole secret is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing in the box yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// CipherBox::encrypt_struct
// ============================================================================

/// The value the encryption is handed is found while it is still holding it.
///
/// # Why this and not the call with nothing to clear it afterwards
///
/// Because there would be nothing left to find: `encrypt_struct` empties what
/// it is handed as it encodes, so a value kept after that call is a value that
/// is already empty, and a test built that way reports an absence the encoding
/// caused rather than a sweep that cannot see.
///
/// So what this holds is the value before the call. It is the same allocation
/// the field keeps its bytes in, reached the same way, and it is what says the
/// absence below is about the box.
#[test]
fn test_the_value_encrypting_is_handed_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    elenchos!({
        let it = value(32);

        capture!();

        core::mem::forget(it);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a value built, and kept");

    Ok(())
}

/// The way in, on its own: a value built inside, encrypted, and cleared.
macro_rules! encrypted {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let (mut one_field_box, key) = a_box()?;

            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            elenchos!({
                let mut it = value($of);

                one_field_box.inner.encrypt_struct(&key, &mut it)?;

                capture!();

                it.fast_zeroize();

                drop(it);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("encrypted {} bytes", $of),
            );

            drop(core::hint::black_box((one_field_box, key)));

            Ok(())
        }
    };
}

encrypted!(test_encrypting_32_bytes_leaves_nothing, 32);
encrypted!(test_encrypting_64_bytes_leaves_nothing, 64);
encrypted!(test_encrypting_128_bytes_leaves_nothing, 128);
encrypted!(test_encrypting_256_bytes_leaves_nothing, 256);
encrypted!(test_encrypting_512_bytes_leaves_nothing, 512);
encrypted!(test_encrypting_1024_bytes_leaves_nothing, 1024);
encrypted!(test_encrypting_4096_bytes_leaves_nothing, 4096);
encrypted!(test_encrypting_32768_bytes_leaves_nothing, 32768);

// ============================================================================
// CipherBox::decrypt_struct
// ============================================================================

/// What came back out is found while whoever asked for it is still holding it.
#[test]
fn test_what_was_decrypted_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (mut one_field_box, key) = a_box()?;

    let mut watch = Forensics::watching(&backwards())?;

    elenchos!({
        let mut it = value(32);

        one_field_box.inner.encrypt_struct(&key, &mut it)?;

        it.fast_zeroize();

        let back = one_field_box.inner.decrypt_struct(&key)?;

        capture!();

        core::mem::forget(back);

        drop(it);
    });

    let report = watch.snapshot()?;

    is_found(&report, "decrypted, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

/// The way out, which is where the plaintext reappears — in the field, in
/// the buffer it was decrypted from, and in whatever the decoder read it
/// through.
macro_rules! decrypted {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let (mut one_field_box, key) = a_box()?;

            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            elenchos!({
                let mut it = value($of);

                one_field_box.inner.encrypt_struct(&key, &mut it)?;

                it.fast_zeroize();

                let back = one_field_box.inner.decrypt_struct(&key)?;

                capture!();

                drop(back);
                drop(it);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("decrypted {} bytes", $of),
            );

            drop(core::hint::black_box((one_field_box, key)));

            Ok(())
        }
    };
}

decrypted!(test_decrypting_32_bytes_leaves_nothing, 32);
decrypted!(test_decrypting_64_bytes_leaves_nothing, 64);
decrypted!(test_decrypting_128_bytes_leaves_nothing, 128);
decrypted!(test_decrypting_256_bytes_leaves_nothing, 256);
decrypted!(test_decrypting_512_bytes_leaves_nothing, 512);
decrypted!(test_decrypting_1024_bytes_leaves_nothing, 1024);
decrypted!(test_decrypting_4096_bytes_leaves_nothing, 4096);
decrypted!(test_decrypting_32768_bytes_leaves_nothing, 32768);
