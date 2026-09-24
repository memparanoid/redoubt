// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each method of a `CipherBox` leaves behind, measured on its own.

use redoubt_aead::Aead;
use redoubt_alloc::RedoubtVec;
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, Reason, capture, forensics};
use redoubt_zero::{FastZeroizable, RedoubtZero};

use crate::cipherbox::CipherBox;
use crate::error::CipherBoxError;
use crate::helpers::{decrypt_from, encrypt_into};
use crate::master_key::leak_master_key;
use crate::traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};
use crate::types::{Ciphertexts, Data, DataBuffers, Nonces, Tags};

use super::support::needles::{backwards, master_key_backwards, master_key_width};
use super::support::{Watched, giving, is_found, leaves_nothing};

#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct OneField {
    all_of_it: RedoubtVec<u8>,
}

impl CipherBoxDyns<1> for OneField {
    fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn Decryptable; 1] {
        [&mut self.all_of_it]
    }

    fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn Encryptable; 1] {
        [&mut self.all_of_it]
    }
}

impl EncryptStruct<1> for OneField {
    fn encrypt_into(
        &mut self,
        aead: &mut Aead,
        aead_key: &[u8],
        nonces: &mut Nonces<1>,
        tags: &mut Tags<1>,
    ) -> Result<Ciphertexts<1>, CipherBoxError> {
        encrypt_into(
            self.to_encryptable_dyn_fields(),
            aead,
            aead_key,
            nonces,
            tags,
        )
    }
}

impl DecryptStruct<1> for OneField {
    fn decrypt_from(
        &mut self,
        aead: &Aead,
        aead_key: &[u8],
        nonces: &Nonces<1>,
        tags: &Tags<1>,
        ciphertexts: &mut Ciphertexts<1>,
    ) -> Result<(), CipherBoxError> {
        decrypt_from(
            &mut self.to_decryptable_dyn_fields(),
            aead,
            aead_key,
            nonces,
            tags,
            ciphertexts,
        )
    }
}

type OneFieldBox = CipherBox<OneField, 1>;

type Field = RedoubtVec<u8>;

/// A value holding `of` bytes of the secret.
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

/// An empty box and a copy of the key it works with, made by the copy that
/// erases what it used: `to_vec` would be the C library's `memcpy`.
fn a_box() -> Result<(OneFieldBox, Vec<u8>), AnyError> {
    let one_field_box = OneFieldBox::new(Aead::default());
    let opened = leak_master_key(master_key_width())?;
    let mut key = vec![0_u8; opened.len()];

    // SAFETY: `key` was made as long as `opened`, and the two are different
    // allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(opened.as_ptr(), key.as_mut_ptr(), key.len()) };

    Ok((one_field_box, key))
}

/// A box sealed over a value of the secret, and the key it was sealed with.
fn sealed() -> Result<(OneFieldBox, Vec<u8>), AnyError> {
    let (mut one_field_box, key) = a_box()?;
    let mut plaintext = value(32);

    one_field_box.encrypt_struct(&key, &mut plaintext)?;

    Ok((one_field_box, key))
}

/// A sealed box, its key's copy emptied, and the photographs after, held to the
/// bound because every test reads a difference from them.
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
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
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

/// `encrypt_struct` empties what it is handed, so there is nothing of it to
/// find after the call: the presence is the value it is handed, before it.
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

/// Most methods let the key go before anything could photograph it, so what
/// vouches for its needle is the same brick, `leak_master_key`, held.
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

                capture(|| one_field_box.encrypt_struct(&key, &mut plaintext))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                //
                // Forgotten and not emptied: emptying it is the operation's.
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

#[test]
fn test_what_was_decrypted_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (mut one_field_box, key) = a_box()?;

    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut plaintext = value(32);

        one_field_box.encrypt_struct(&key, &mut plaintext)?;

        // The input emptied, so what is found is what came back out.
        plaintext.fast_zeroize();

        let back = capture(|| one_field_box.decrypt_struct(&key))?;

        core::mem::forget(back);

        drop(plaintext);
    });

    let report = watch.snapshot()?;

    is_found(&report, "decrypted, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

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

                one_field_box.encrypt_struct(&key, &mut plaintext)?;

                // The input emptied, so what is left is this call's.
                plaintext.fast_zeroize();

                let back = capture(|| one_field_box.decrypt_struct(&key))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
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
fn test_what_was_decrypted_from_buffers_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (one_field_box, key) = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut data: DataBuffers<1> =
            core::array::from_fn(|i| one_field_box.__unsafe_get_ciphertexts()[i].clone());

        let back = capture(|| one_field_box.decrypt_struct_from(&key, &mut data))?;

        core::mem::forget(back);
        drop(data);
    });

    is_found(&watch.snapshot()?, "decrypted from buffers, and kept");

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

#[test]
fn test_decrypting_a_struct_from_buffers_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let (one_field_box, mut key) = sealed()?;

    forensics!({
        let mut data: DataBuffers<1> =
            core::array::from_fn(|i| one_field_box.__unsafe_get_ciphertexts()[i].clone());

        let back = capture(|| one_field_box.decrypt_struct_from(&key, &mut data))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(back);
        drop(data);
        key.fast_zeroize();
    });

    watched.none_left("nothing sealed yet", "decrypted from buffers")?;

    drop(core::hint::black_box((one_field_box, key)));

    Ok(())
}

// ============================================================================
// CipherBox::maybe_initialize
// ============================================================================

#[test]
fn test_sealing_an_unsealed_box_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut one_field_box = OneFieldBox::new(Aead::default());

    forensics!({
        capture(|| one_field_box.maybe_initialize())?;
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

        capture(|| one_field_box.try_decrypt_field::<Field, 0>(&key, &mut field, &mut data))?;

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

        capture(|| one_field_box.try_decrypt_field::<Field, 0>(&key, &mut field, &mut data))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

        capture(|| one_field_box.decrypt_field::<Field, 0>(&key, &mut field))?;

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

        capture(|| one_field_box.decrypt_field::<Field, 0>(&key, &mut field))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

        capture(|| one_field_box.decrypt_field_into::<Field, 0>(&key, &mut field, &mut data))?;

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

        capture(|| one_field_box.decrypt_field_into::<Field, 0>(&key, &mut field, &mut data))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

        capture(|| one_field_box.try_encrypt_field::<Field, 0>(&key, &mut field))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying it is the operation's.
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

        capture(|| one_field_box.encrypt_field::<Field, 0>(&key, &mut field))?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying it is the operation's.
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

    one_field_box.open_dyn(&mut |_: &OneField| {
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
        capture(|| one_field_box.open_dyn(&mut |_: &OneField| Ok::<(), CipherBoxError>(())))?;
    });

    watched.none_left("sealed, nothing opened", "opened through a dyn")
}

#[test]
fn test_opening_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box.open_dyn(&mut |_: &OneField| Err::<(), _>(CipherBoxError::Zeroized))
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
        let seen = capture(|| one_field_box.open_value())?;

        core::mem::forget(seen);
    });

    is_found(&watched.secret.snapshot()?, "the value a read sees, kept");

    Ok(())
}

#[test]
fn test_the_value_a_read_sees_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.open_value())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

    one_field_box.open_mut_dyn(&mut |_: &mut OneField| {
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
            one_field_box.open_mut_dyn(&mut |_: &mut OneField| Ok::<(), CipherBoxError>(()))
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

    one_field_box.open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| {
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
            one_field_box.open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| Ok(()))
        })?;
    });

    watched.none_left("sealed, nothing opened", "a field opened through a dyn")
}

#[test]
fn test_opening_a_field_through_a_dyn_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let failed = capture(|| {
            one_field_box.open_field_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &Field| {
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
        let seen = capture(|| one_field_box.open_field_value::<Field, 0>())?;

        core::mem::forget(seen);
    });

    is_found(&watched.secret.snapshot()?, "the field a read sees, kept");

    Ok(())
}

#[test]
fn test_the_field_a_read_sees_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let seen = capture(|| one_field_box.open_field_value::<Field, 0>())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

    one_field_box.open_field_mut_dyn::<Field, 0, (), CipherBoxError>(&mut |_: &mut Field| {
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
            one_field_box.open_field_mut_dyn::<Field, 0, (), CipherBoxError>(
                &mut |_: &mut Field| Err(CipherBoxError::Zeroized),
            )
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

    one_field_box.open(|_: &OneField| {
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
        capture(|| one_field_box.open(|_: &OneField| Ok::<(), CipherBoxError>(())))?;
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

    one_field_box.open_mut(|_: &mut OneField| {
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
        capture(|| one_field_box.open_mut(|_: &mut OneField| Ok::<(), CipherBoxError>(())))?;
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

    one_field_box.open_field::<Field, 0, _, (), CipherBoxError>(|_: &Field| {
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
            one_field_box.open_field::<Field, 0, _, (), CipherBoxError>(|_: &Field| Ok(()))
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

    one_field_box.open_field_mut::<Field, 0, _, (), CipherBoxError>(|_: &mut Field| {
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
            one_field_box.open_field_mut::<Field, 0, _, (), CipherBoxError>(|_: &mut Field| Ok(()))
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
        let taken = capture(|| one_field_box.leak_field::<Field, 0, CipherBoxError>())?;

        core::mem::forget(taken);
    });

    is_found(&watched.secret.snapshot()?, "a leaked field, kept");

    Ok(())
}

#[test]
fn test_leaking_a_field_of_a_cipherbox_leaves_nothing() -> Result<(), AnyError> {
    let (one_field_box, mut watched) = sealed_and_watched()?;

    forensics!({
        let taken = capture(|| one_field_box.leak_field::<Field, 0, CipherBoxError>())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(taken);
    });

    watched.none_left("sealed, nothing opened", "a field of a cipherbox leaked")
}
