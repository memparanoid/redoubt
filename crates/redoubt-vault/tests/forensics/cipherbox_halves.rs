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
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_vault::{cipherbox, leak_master_key};
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::support::needles::{backwards, master_key_backwards, master_key_width};
use crate::support::{giving, is_found, leaves_nothing};

#[cipherbox(OneFieldBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct OneField {
    all_of_it: RedoubtVec<u8>,
}

/// A value of that many bytes of the secret, filled the clean way.
fn value(of: usize) -> OneField {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    let mut one_field = OneField::default();

    one_field.all_of_it.replace_from_mut_slice(&mut source);

    one_field
}

fn a_box() -> Result<(OneFieldBox, Vec<u8>), AnyError> {
    let one_field_box = OneFieldBox::new();
    let opened = leak_master_key(master_key_width())?;
    let mut key = vec![0_u8; opened.len()];

    // SAFETY: `key` was made as long as `opened`, and the two are different
    // allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(opened.as_ptr(), key.as_mut_ptr(), key.len()) };

    Ok((one_field_box, key))
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

    forensics!({
        let plaintext = capture(|| value(32));

        core::mem::forget(plaintext);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a value built, and kept");

    Ok(())
}

#[test]
fn test_the_master_key_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&master_key_backwards()?)?;

    forensics!({
        let held = capture(|| leak_master_key(master_key_width()))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the master key, held");

    Ok(())
}

/// The way in, on its own: a value built inside, encrypted, and cleared.
macro_rules! encrypted {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;
            let mut key_watch = Forensics::watching(&master_key_backwards()?)?;

            let report_before = watch.snapshot()?;
            let key_report_before = key_watch.snapshot()?;

            let (mut one_field_box, mut key) = a_box()?;

            forensics!({
                let mut plaintext = value($of);

                capture(|| one_field_box.inner.encrypt_struct(&key, &mut plaintext))?;

                core::mem::forget(plaintext);

                key.fast_zeroize();
            });

            let report_after = watch.snapshot()?;
            let key_report_after = key_watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing in the box yet",
                &report_after,
                &format!("encrypted {} bytes", $of),
            );

            leaves_nothing(
                &key_report_before,
                "no key opened yet",
                &key_report_after,
                &format!("the key, after encrypting {} bytes", $of),
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

    forensics!({
        let mut plaintext = value(32);

        one_field_box.inner.encrypt_struct(&key, &mut plaintext)?;

        plaintext.fast_zeroize();

        let back = capture(|| one_field_box.inner.decrypt_struct(&key))?;

        core::mem::forget(back);

        drop(plaintext);
    });

    let report = watch.snapshot()?;

    is_found(&report, "decrypted, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

#[test]
#[ignore = "Covered transitively: the key's presence is the same brick, \
            `leak_master_key` held, measured in the `encrypt_struct` section."]
fn test_the_master_key_decrypting_uses_is_found_while_it_is_held() {
    // Intentionally empty.
}

/// The way out, which is where the plaintext reappears — in the field, in
/// the buffer it was decrypted from, and in whatever the decoder read it
/// through.
macro_rules! decrypted {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;
            let mut key_watch = Forensics::watching(&master_key_backwards()?)?;

            let report_before = watch.snapshot()?;
            let key_report_before = key_watch.snapshot()?;

            let (mut one_field_box, mut key) = a_box()?;

            forensics!({
                let mut plaintext = value($of);

                one_field_box.inner.encrypt_struct(&key, &mut plaintext)?;

                plaintext.fast_zeroize();

                let back = capture(|| one_field_box.inner.decrypt_struct(&key))?;

                drop(back);
                drop(plaintext);

                key.fast_zeroize();
            });

            let report_after = watch.snapshot()?;
            let key_report_after = key_watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing in the box yet",
                &report_after,
                &format!("decrypted {} bytes", $of),
            );

            leaves_nothing(
                &key_report_before,
                "no key opened yet",
                &key_report_after,
                &format!("the key, after decrypting {} bytes", $of),
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
