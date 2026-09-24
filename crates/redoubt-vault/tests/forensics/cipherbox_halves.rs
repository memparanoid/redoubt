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
use redoubt_forensics::{AnyError, Forensics, QUIET, Reason, capture, forensics};
use redoubt_vault::{CipherBoxError, Data, cipherbox, leak_master_key};
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::support::needles::{backwards, master_key_backwards, master_key_width};
use crate::support::{Watched, giving, is_found, leaves_nothing};

#[cipherbox(OneFieldBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct OneField {
    all_of_it: RedoubtVec<u8>,
}

type Field = RedoubtVec<u8>;

/// A value of that many bytes of the secret, filled the clean way.
fn value(of: usize) -> OneField {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    let mut one_field = OneField::default();

    one_field.all_of_it.replace_from_mut_slice(&mut source);

    one_field
}

fn a_field() -> Box<Field> {
    let mut source = vec![0_u8; 32];

    giving(&mut source);

    let mut field = Box::new(Field::default());

    field.replace_from_mut_slice(&mut source);

    field
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

fn sealed() -> Result<(OneFieldBox, Vec<u8>), AnyError> {
    let (mut one_field_box, key) = a_box()?;
    let mut plaintext = value(32);

    one_field_box.inner.encrypt_struct(&key, &mut plaintext)?;

    Ok((one_field_box, key))
}

fn sealed_and_watched() -> Result<(OneFieldBox, Watched), AnyError> {
    let (one_field_box, mut key) = sealed()?;

    key.fast_zeroize();
    drop(key);

    let watched = Watched::start()?;

    for (report, what) in watched.befores() {
        assert!(
            !report.found,
            "the whole of {what} was left behind by sealing the box: {report}"
        );

        assert!(
            report.widest <= QUIET,
            "a run of {} bytes of {what} was left behind by sealing the box, and \
             {QUIET} is what memory has by accident: {report}",
            report.widest,
        );
    }

    Ok((one_field_box, watched))
}

// ============================================================================
// CipherBox::drop
// ============================================================================

#[test]
fn test_a_cipherbox_dropped_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| drop(one_field_box));
    });

    watched.none_left("sealed, nothing opened", "a cipherbox dropped")
}

// ============================================================================
// CipherBox::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty box."]
fn test_making_a_cipherbox_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// CipherBox::assert_healthy
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads two flags."]
fn test_asserting_a_cipherbox_is_healthy_leaves_nothing() {
    // Intentionally empty.
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

// ============================================================================
// CipherBox::decrypt_struct_from
// ============================================================================

#[test]
#[ignore = "Reached only through `decrypt_struct`, measured in its section: the \
            buffers it decrypts are the box's ciphertexts, which nothing outside \
            the crate can read."]
fn test_decrypting_a_struct_from_buffers_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// CipherBox::maybe_initialize
// ============================================================================

#[test]
fn test_sealing_an_unsealed_box_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut one_field_box = OneFieldBox::new();

    forensics!({
        capture(|| one_field_box.inner.maybe_initialize())?;
    });

    watched.none_left("nothing sealed yet", "an unsealed box sealed")?;

    drop(core::hint::black_box(one_field_box));

    Ok(())
}

// ============================================================================
// CipherBox::try_decrypt_field
// ============================================================================

#[test]
fn test_what_a_field_was_tried_into_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, key) = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut field = Box::new(Field::default());
        let mut data = Data::default();

        capture(|| {
            one_field_box
                .inner
                .try_decrypt_field::<Field, 0>(&key, &mut field, &mut data)
        })?;

        core::mem::forget(field);
        drop(data);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field tried, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

#[test]
fn test_trying_to_decrypt_a_field_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (one_field_box, mut key) = sealed()?;

    forensics!({
        let mut field = Box::new(Field::default());
        let mut data = Data::default();

        capture(|| {
            one_field_box
                .inner
                .try_decrypt_field::<Field, 0>(&key, &mut field, &mut data)
        })?;

        field.fast_zeroize();
        drop(data);
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "a field tried")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::decrypt_field
// ============================================================================

#[test]
fn test_what_a_field_was_decrypted_into_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, key) = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut field = Box::new(Field::default());

        capture(|| {
            one_field_box
                .inner
                .decrypt_field::<Field, 0>(&key, &mut field)
        })?;

        core::mem::forget(field);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field decrypted, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

#[test]
fn test_decrypting_a_field_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (one_field_box, mut key) = sealed()?;

    forensics!({
        let mut field = Box::new(Field::default());

        capture(|| {
            one_field_box
                .inner
                .decrypt_field::<Field, 0>(&key, &mut field)
        })?;

        field.fast_zeroize();
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "a field decrypted")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::decrypt_field_into
// ============================================================================

#[test]
fn test_what_a_field_was_decrypted_into_through_a_buffer_is_found_while_it_is_held()
-> Result<(), AnyError> {
    let (one_field_box, key) = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut field = Box::new(Field::default());
        let mut data = Data::default();

        capture(|| {
            one_field_box
                .inner
                .decrypt_field_into::<Field, 0>(&key, &mut field, &mut data)
        })?;

        core::mem::forget(field);
        drop(data);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field decrypted through a buffer, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

#[test]
fn test_decrypting_a_field_into_a_buffer_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (one_field_box, mut key) = sealed()?;

    forensics!({
        let mut field = Box::new(Field::default());
        let mut data = Data::default();

        capture(|| {
            one_field_box
                .inner
                .decrypt_field_into::<Field, 0>(&key, &mut field, &mut data)
        })?;

        field.fast_zeroize();
        drop(data);
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "a field decrypted through a buffer")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::try_encrypt_field
// ============================================================================

#[test]
fn test_trying_to_encrypt_a_field_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (mut one_field_box, mut key) = sealed()?;

    forensics!({
        let mut field = a_field();

        capture(|| {
            one_field_box
                .inner
                .try_encrypt_field::<Field, 0>(&key, &mut field)
        })?;

        core::mem::forget(field);
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "a field tried into the box")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::encrypt_field
// ============================================================================

#[test]
fn test_encrypting_a_field_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (mut one_field_box, mut key) = sealed()?;

    forensics!({
        let mut field = a_field();

        capture(|| {
            one_field_box
                .inner
                .encrypt_field::<Field, 0>(&key, &mut field)
        })?;

        core::mem::forget(field);
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "a field encrypted into the box")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::open_dyn
// ============================================================================

#[test]
fn test_the_secret_is_found_while_it_is_open_through_a_dyn() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;

    one_field_box.inner.open_dyn(&mut |_: &OneField| {
        inside = watched.secret.snapshot().ok();

        Ok::<(), CipherBoxError>(())
    })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, open through a dyn",
    );

    Ok(())
}

#[test]
fn test_opening_through_a_dyn_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_dyn(&mut |_: &OneField| Ok::<(), CipherBoxError>(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "opened through a dyn")
}

#[test]
fn test_opening_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box
                .inner
                .open_dyn(&mut |_: &OneField| Err::<(), _>(CipherBoxError::Zeroized))
        });

        core::hint::black_box(failed.is_err());
    });

    watched.none_left("sealed, nothing opened", "opened through a dyn, and failed")
}

// ============================================================================
// CipherBox::open_value
// ============================================================================

#[test]
fn test_the_value_a_read_sees_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.inner.open_value())?;

        core::mem::forget(seen);
    });

    is_found(&watched.secret.snapshot()?, "the value a read sees, kept");

    Ok(())
}

#[test]
fn test_the_value_a_read_sees_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.inner.open_value())?;

        drop(seen);
    });

    watched.none_left("sealed, nothing opened", "the value a read sees")
}

// ============================================================================
// CipherBox::open_mut_dyn
// ============================================================================

#[test]
fn test_the_secret_is_found_while_it_is_open_for_writing_through_a_dyn() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;
    let mut key_inside = None;

    one_field_box.inner.open_mut_dyn(&mut |_: &mut OneField| {
        inside = watched.secret.snapshot().ok();
        key_inside = watched.key.snapshot().ok();

        Ok::<(), CipherBoxError>(())
    })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, open for writing through a dyn",
    );
    is_found(
        &key_inside.ok_or(Reason::NoAnswer)?,
        "the master key, open for writing through a dyn",
    );

    Ok(())
}

#[test]
fn test_opening_for_writing_through_a_dyn_leaves_nothing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_mut_dyn(&mut |_: &mut OneField| Ok::<(), CipherBoxError>(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "opened for writing through a dyn")
}

#[test]
fn test_opening_for_writing_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box
                .inner
                .open_mut_dyn(&mut |_: &mut OneField| Err::<(), _>(CipherBoxError::Zeroized))
        });

        core::hint::black_box(failed.is_err());
    });

    watched.none_left(
        "sealed, nothing opened",
        "opened for writing through a dyn, and failed",
    )
}

// ============================================================================
// CipherBox::open_field_dyn
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_field_is_open_through_a_dyn() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;

    one_field_box
        .inner
        .open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| {
            inside = watched.secret.snapshot().ok();

            Ok(())
        })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a field open through a dyn",
    );

    Ok(())
}

#[test]
fn test_opening_a_field_through_a_dyn_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| Ok(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "a field opened through a dyn")
}

#[test]
fn test_opening_a_field_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box
                .inner
                .open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| {
                    Err(CipherBoxError::Zeroized)
                })
        });

        core::hint::black_box(failed.is_err());
    });

    watched.none_left(
        "sealed, nothing opened",
        "a field opened through a dyn, and failed",
    )
}

// ============================================================================
// CipherBox::open_field_value
// ============================================================================

#[test]
fn test_the_field_a_read_sees_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.inner.open_field_value::<Field, 0>())?;

        core::mem::forget(seen);
    });

    is_found(&watched.secret.snapshot()?, "the field a read sees, kept");

    Ok(())
}

#[test]
fn test_the_field_a_read_sees_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.inner.open_field_value::<Field, 0>())?;

        drop(seen);
    });

    watched.none_left("sealed, nothing opened", "the field a read sees")
}

// ============================================================================
// CipherBox::open_field_mut_dyn
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_field_is_open_for_writing_through_a_dyn() -> Result<(), AnyError>
{
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;
    let mut key_inside = None;

    one_field_box
        .inner
        .open_field_mut_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &mut Field| {
            inside = watched.secret.snapshot().ok();
            key_inside = watched.key.snapshot().ok();

            Ok(())
        })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a field open for writing through a dyn",
    );
    is_found(
        &key_inside.ok_or(Reason::NoAnswer)?,
        "the master key, a field open for writing through a dyn",
    );

    Ok(())
}

#[test]
fn test_opening_a_field_for_writing_through_a_dyn_leaves_nothing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_field_mut_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &mut Field| Ok(()))
        })?;
    });

    watched.none_left(
        "sealed, nothing opened",
        "a field opened for writing through a dyn",
    )
}

#[test]
fn test_opening_a_field_for_writing_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError>
{
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box
                .inner
                .open_field_mut_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &mut Field| {
                    Err(CipherBoxError::Zeroized)
                })
        });

        core::hint::black_box(failed.is_err());
    });

    watched.none_left(
        "sealed, nothing opened",
        "a field opened for writing through a dyn, and failed",
    )
}

// ============================================================================
// CipherBox::open
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_cipherbox_is_open() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;

    one_field_box.inner.open(|_: &OneField| {
        inside = watched.secret.snapshot().ok();

        Ok::<(), CipherBoxError>(())
    })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a cipherbox open",
    );

    Ok(())
}

#[test]
fn test_opening_a_cipherbox_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open(|_: &OneField| Ok::<(), CipherBoxError>(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "a cipherbox opened")
}

// ============================================================================
// CipherBox::open_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_cipherbox_is_open_for_writing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;
    let mut key_inside = None;

    one_field_box.inner.open_mut(|_: &mut OneField| {
        inside = watched.secret.snapshot().ok();
        key_inside = watched.key.snapshot().ok();

        Ok::<(), CipherBoxError>(())
    })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a cipherbox open for writing",
    );
    is_found(
        &key_inside.ok_or(Reason::NoAnswer)?,
        "the master key, a cipherbox open for writing",
    );

    Ok(())
}

#[test]
fn test_opening_a_cipherbox_for_writing_leaves_nothing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_mut(|_: &mut OneField| Ok::<(), CipherBoxError>(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "a cipherbox opened for writing")
}

// ============================================================================
// CipherBox::open_field
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_field_of_a_cipherbox_is_open() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;

    one_field_box
        .inner
        .open_field::<Field, 0, _, (), CipherBoxError>(|_: &Field| {
            inside = watched.secret.snapshot().ok();

            Ok(())
        })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a field of a cipherbox open",
    );

    Ok(())
}

#[test]
fn test_opening_a_field_of_a_cipherbox_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_field::<Field, 0, _, (), CipherBoxError>(|_: &Field| Ok(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "a field of a cipherbox opened")
}

// ============================================================================
// CipherBox::open_field_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_field_of_a_cipherbox_is_open_for_writing()
-> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    let mut inside = None;
    let mut key_inside = None;

    one_field_box
        .inner
        .open_field_mut::<Field, 0, _, (), CipherBoxError>(|_: &mut Field| {
            inside = watched.secret.snapshot().ok();
            key_inside = watched.key.snapshot().ok();

            Ok(())
        })?;

    is_found(
        &inside.ok_or(Reason::NoAnswer)?,
        "the secret, a field of a cipherbox open for writing",
    );
    is_found(
        &key_inside.ok_or(Reason::NoAnswer)?,
        "the master key, a field of a cipherbox open for writing",
    );

    Ok(())
}

#[test]
fn test_opening_a_field_of_a_cipherbox_for_writing_leaves_nothing() -> Result<(), AnyError> {
    let (mut one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        capture(|| {
            one_field_box
                .inner
                .open_field_mut::<Field, 0, _, (), CipherBoxError>(|_: &mut Field| Ok(()))
        })?;
    });

    watched.none_left(
        "sealed, nothing opened",
        "a field of a cipherbox opened for writing",
    )
}

// ============================================================================
// CipherBox::leak_field
// ============================================================================

#[test]
fn test_what_a_field_of_a_cipherbox_leaked_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let taken = capture(|| one_field_box.inner.leak_field::<Field, 0, CipherBoxError>())?;

        core::mem::forget(taken);
    });

    is_found(&watched.secret.snapshot()?, "a leaked field, kept");

    Ok(())
}

#[test]
fn test_leaking_a_field_of_a_cipherbox_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let taken = capture(|| one_field_box.inner.leak_field::<Field, 0, CipherBoxError>())?;

        drop(taken);
    });

    watched.none_left("sealed, nothing opened", "a field of a cipherbox leaked")
}
