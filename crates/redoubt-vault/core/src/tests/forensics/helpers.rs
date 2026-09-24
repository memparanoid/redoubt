// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What encrypting and decrypting the fields of a struct leaves behind.

use redoubt_aead::{Aead, AeadBehaviour};
use redoubt_alloc::RedoubtVec;
use redoubt_codec::{Decode, DecodeError, RedoubtCodecBuffer};
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::error::CipherBoxError;
use crate::helpers::{
    decrypt_from, encrypt_into, encrypt_into_buffers, get_sizes, to_decryptable_mut_dyn,
    to_encryptable_mut_dyn, try_decrypt_from, try_encrypt_into_buffers,
};
use crate::master_key::leak_master_key;
use crate::types::{Ciphertexts, Nonces, Tags};

use super::support::needles::{backwards, master_key_backwards, master_key_width};
use super::support::{Watched, a_field, a_key, is_found};

type Field = RedoubtVec<u8>;

fn nonces_and_tags(aead: &Aead) -> (Nonces<2>, Tags<2>) {
    (
        core::array::from_fn(|_| vec![0_u8; aead.nonce_size()]),
        core::array::from_fn(|_| vec![0_u8; aead.tag_size()]),
    )
}

fn buffers_for(first: &mut Field, second: &mut Field) -> Result<[RedoubtCodecBuffer; 2], AnyError> {
    let sizes = get_sizes(&[
        to_encryptable_mut_dyn(first),
        to_encryptable_mut_dyn(second),
    ])?;

    Ok(sizes.map(RedoubtCodecBuffer::with_capacity))
}

struct Sealed {
    nonces: Nonces<2>,
    tags: Tags<2>,
    ciphertexts: Ciphertexts<2>,
}

/// Two fields of the secret encrypted, and the key's copy they took emptied.
fn sealed() -> Result<Sealed, AnyError> {
    let mut aead = Aead::default();
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);
    let (mut first, mut second) = (a_field(), a_field());

    let ciphertexts = encrypt_into(
        [
            to_encryptable_mut_dyn(&mut first),
            to_encryptable_mut_dyn(&mut second),
        ],
        &mut aead,
        &key,
        &mut nonces,
        &mut tags,
    )?;

    key.fast_zeroize();

    Ok(Sealed {
        nonces,
        tags,
        ciphertexts,
    })
}

/// A field that refuses to decode and leaves the buffer as it was: the codec's
/// own types empty it when they fail, and the wipe after them would go
/// unmeasured.
struct Refusing;

impl Decode for Refusing {
    fn decode_from(&mut self, _: &mut &mut [u8]) -> Result<(), DecodeError> {
        Err(DecodeError::IntentionalDecodeError)
    }
}

impl FastZeroizable for Refusing {
    fn fast_zeroize(&mut self) {}
}

// ============================================================================
// get_sizes
// ============================================================================

#[test]
#[ignore = "Reads no secret: it asks each field how many bytes it encodes to."]
fn test_sizing_the_fields_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// encrypt_into
// ============================================================================

/// Encrypting empties the fields it is handed, so the presence is a field
/// before it.
#[test]
fn test_the_field_encrypting_is_handed_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let field = capture(a_field);

        core::mem::forget(field);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field built, and kept");

    Ok(())
}

/// Nothing here holds the key after it returns, so what vouches for its needle
/// is `leak_master_key`, held.
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

#[test]
fn test_encrypting_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut aead = Aead::default();
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);

    forensics!({
        let (mut first, mut second) = (a_field(), a_field());

        let ciphertexts = capture(|| {
            encrypt_into(
                [
                    to_encryptable_mut_dyn(&mut first),
                    to_encryptable_mut_dyn(&mut second),
                ],
                &mut aead,
                &key,
                &mut nonces,
                &mut tags,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second));

        key.fast_zeroize();

        drop(ciphertexts);
    });

    watched.none_left("nothing encrypted yet", "encrypting")
}

// ============================================================================
// try_encrypt_into_buffers
// ============================================================================

#[test]
fn test_what_encrypting_exported_and_did_not_encrypt_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(2));
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);

    forensics!({
        let (mut first, mut second) = (a_field(), a_field());
        let mut buffers = buffers_for(&mut first, &mut second)?;
        let mut ciphertexts: Ciphertexts<2> = core::array::from_fn(|_| vec![]);

        let refused = capture(|| {
            try_encrypt_into_buffers(
                [
                    to_encryptable_mut_dyn(&mut first),
                    to_encryptable_mut_dyn(&mut second),
                ],
                &mut aead,
                &key,
                &mut nonces,
                &mut tags,
                &mut buffers,
                &mut ciphertexts,
            )
        });

        assert!(
            matches!(refused, Err(CipherBoxError::Aead(_))),
            "the second encryption was not refused: {refused:?}"
        );

        core::mem::forget((first, second, buffers, ciphertexts));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field exported, and not encrypted");

    key.fast_zeroize();

    Ok(())
}

#[test]
fn test_trying_to_encrypt_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut aead = Aead::default();
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);

    forensics!({
        let (mut first, mut second) = (a_field(), a_field());
        let mut buffers = buffers_for(&mut first, &mut second)?;
        let mut ciphertexts: Ciphertexts<2> = core::array::from_fn(|_| vec![]);

        capture(|| {
            try_encrypt_into_buffers(
                [
                    to_encryptable_mut_dyn(&mut first),
                    to_encryptable_mut_dyn(&mut second),
                ],
                &mut aead,
                &key,
                &mut nonces,
                &mut tags,
                &mut buffers,
                &mut ciphertexts,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second, buffers));

        key.fast_zeroize();

        drop(ciphertexts);
    });

    watched.none_left("nothing encrypted yet", "trying to encrypt")
}

// ============================================================================
// encrypt_into_buffers
// ============================================================================

#[test]
fn test_encrypting_into_buffers_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut aead = Aead::default();
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);

    forensics!({
        let (mut first, mut second) = (a_field(), a_field());
        let mut buffers = buffers_for(&mut first, &mut second)?;
        let mut ciphertexts: Ciphertexts<2> = core::array::from_fn(|_| vec![]);

        capture(|| {
            encrypt_into_buffers(
                [
                    to_encryptable_mut_dyn(&mut first),
                    to_encryptable_mut_dyn(&mut second),
                ],
                &mut aead,
                &key,
                &mut nonces,
                &mut tags,
                &mut buffers,
                &mut ciphertexts,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second, buffers));

        key.fast_zeroize();

        drop(ciphertexts);
    });

    watched.none_left("nothing encrypted yet", "encrypting into buffers")
}

#[test]
fn test_encrypting_into_buffers_refused_leaves_nothing() -> Result<(), AnyError> {
    let mut watched = Watched::start()?;

    let mut aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(2));
    let mut key = a_key()?;
    let (mut nonces, mut tags) = nonces_and_tags(&aead);

    forensics!({
        let (mut first, mut second) = (a_field(), a_field());
        let mut buffers = buffers_for(&mut first, &mut second)?;
        let mut ciphertexts: Ciphertexts<2> = core::array::from_fn(|_| vec![]);

        let refused = capture(|| {
            encrypt_into_buffers(
                [
                    to_encryptable_mut_dyn(&mut first),
                    to_encryptable_mut_dyn(&mut second),
                ],
                &mut aead,
                &key,
                &mut nonces,
                &mut tags,
                &mut buffers,
                &mut ciphertexts,
            )
        });

        assert!(
            matches!(refused, Err(CipherBoxError::Poisoned)),
            "the second encryption was not refused: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Forgotten and not emptied: emptying them is the operation's.
        core::mem::forget((first, second, buffers, ciphertexts));

        key.fast_zeroize();
    });

    watched.none_left("nothing encrypted yet", "encrypting into buffers, refused")
}

// ============================================================================
// try_decrypt_from
// ============================================================================

#[test]
fn test_what_decrypting_decoded_is_found_while_the_fields_hold_it() -> Result<(), AnyError> {
    let mut sealed = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    let aead = Aead::default();
    let mut key = a_key()?;

    forensics!({
        let (mut first, mut second) = (Field::default(), Field::default());

        capture(|| {
            try_decrypt_from(
                &mut [
                    to_decryptable_mut_dyn(&mut first),
                    to_decryptable_mut_dyn(&mut second),
                ],
                &aead,
                &key,
                &sealed.nonces,
                &sealed.tags,
                &mut sealed.ciphertexts,
            )
        })?;

        core::mem::forget((first, second));
    });

    let report = watch.snapshot()?;

    is_found(&report, "the fields decoded, and kept");

    key.fast_zeroize();

    Ok(())
}

#[test]
fn test_what_decrypting_decrypted_and_did_not_decode_is_found() -> Result<(), AnyError> {
    let mut sealed = sealed()?;

    let mut watch = Forensics::watching(&backwards())?;

    let aead = Aead::default();
    let mut key = a_key()?;

    forensics!({
        let (mut first, mut second) = (Field::default(), Refusing);

        let refused = capture(|| {
            try_decrypt_from(
                &mut [
                    to_decryptable_mut_dyn(&mut first),
                    to_decryptable_mut_dyn(&mut second),
                ],
                &aead,
                &key,
                &sealed.nonces,
                &sealed.tags,
                &mut sealed.ciphertexts,
            )
        });

        assert!(
            matches!(refused, Err(CipherBoxError::Decode(_))),
            "the second field decoded: {refused:?}"
        );

        // Emptied, so what is found can only be what was decrypted and not
        // decoded.
        first.fast_zeroize();

        core::mem::forget(sealed);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a field decrypted, and not decoded");

    key.fast_zeroize();

    Ok(())
}

#[test]
fn test_trying_to_decrypt_leaves_nothing() -> Result<(), AnyError> {
    let mut sealed = sealed()?;

    let mut watched = Watched::start()?;

    let aead = Aead::default();
    let mut key = a_key()?;

    forensics!({
        let (mut first, mut second) = (Field::default(), Field::default());

        capture(|| {
            try_decrypt_from(
                &mut [
                    to_decryptable_mut_dyn(&mut first),
                    to_decryptable_mut_dyn(&mut second),
                ],
                &aead,
                &key,
                &sealed.nonces,
                &sealed.tags,
                &mut sealed.ciphertexts,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        first.fast_zeroize();
        second.fast_zeroize();

        key.fast_zeroize();

        // Forgotten and not emptied: emptying the ciphertexts is the
        // operation's.
        core::mem::forget(sealed);
    });

    watched.none_left("sealed, nothing decrypted", "trying to decrypt")
}

// ============================================================================
// decrypt_from
// ============================================================================

#[test]
fn test_decrypting_leaves_nothing() -> Result<(), AnyError> {
    let mut sealed = sealed()?;

    let mut watched = Watched::start()?;

    let aead = Aead::default();
    let mut key = a_key()?;

    forensics!({
        let (mut first, mut second) = (Field::default(), Field::default());

        capture(|| {
            decrypt_from(
                &mut [
                    to_decryptable_mut_dyn(&mut first),
                    to_decryptable_mut_dyn(&mut second),
                ],
                &aead,
                &key,
                &sealed.nonces,
                &sealed.tags,
                &mut sealed.ciphertexts,
            )
        })?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        first.fast_zeroize();
        second.fast_zeroize();

        key.fast_zeroize();

        // Forgotten and not emptied: emptying the ciphertexts is the
        // operation's.
        core::mem::forget(sealed);
    });

    watched.none_left("sealed, nothing decrypted", "decrypting")
}

#[test]
fn test_decrypting_refused_leaves_nothing() -> Result<(), AnyError> {
    let mut sealed = sealed()?;

    let mut watched = Watched::start()?;

    let aead = Aead::default();
    let mut key = a_key()?;

    forensics!({
        let (mut first, mut second) = (Field::default(), Refusing);

        let refused = capture(|| {
            decrypt_from(
                &mut [
                    to_decryptable_mut_dyn(&mut first),
                    to_decryptable_mut_dyn(&mut second),
                ],
                &aead,
                &key,
                &sealed.nonces,
                &sealed.tags,
                &mut sealed.ciphertexts,
            )
        });

        assert!(
            matches!(refused, Err(CipherBoxError::Poisoned)),
            "the second field decoded: {refused:?}"
        );

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        first.fast_zeroize();

        key.fast_zeroize();

        // Forgotten and not emptied: emptying the ciphertexts is the
        // operation's.
        core::mem::forget(sealed);
    });

    watched.none_left("sealed, nothing decrypted", "decrypting, refused")
}
