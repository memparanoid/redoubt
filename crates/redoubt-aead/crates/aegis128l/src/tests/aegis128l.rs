// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the construction leaves the caller holding.
//!
//! There is no test here that the type empties itself, because it holds
//! nothing to empty: the state lives in the vector registers for the length of
//! a call, and what says those come back clean is the probe in `probes` and the
//! four cases in `asm`.

use std::vec;

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadCoreError, AeadDecrypt, AeadEncrypt};
use redoubt_zero::ZeroizationProbe;

use crate::aegis128l::Aegis128L;

const KEY: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
const NONCE: [u8; NONCE_SIZE] = [0x17; NONCE_SIZE];

/// Every way a message can sit against the thirty-two bytes the state absorbs
/// at a time, and one long enough to go round the loop many times.
const LENGTHS: [usize; 11] = [1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1024];

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

/// A tag that does not match leaves the caller's buffer empty.
///
/// AEGIS is one pass, so what is in that buffer at that moment is not the
/// ciphertext that arrived — it is the plaintext this deciphered out of it,
/// before there was a tag to compare. A caller that ignores the error and reads
/// on would read exactly what an attacker wanted deciphered, which is the whole
/// of what authentication is for.
///
/// Every length is asked, because the wipe is over a slice and one that covered
/// whole blocks only would leave the tail of anything that does not end on one.
#[test]
fn test_decrypt_empties_the_buffer_when_the_tag_does_not_match() {
    let mut aead = Aegis128L::new();

    for length in LENGTHS {
        let mut data = vec![0xAB_u8; length];
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&KEY, &NONCE, b"", &mut data, &mut tag);

        // What makes the reading below mean anything: the buffer has to be
        // holding something on the way in, or an emptiness afterwards says only
        // that it was empty already.
        assert!(
            !data.is_zeroized(),
            "the ciphertext to be refused is already empty, {length} bytes in"
        );

        tag[0] ^= 1;

        let refused = aead.decrypt(&KEY, &NONCE, b"", &mut data, &tag);

        assert_eq!(
            refused,
            Err(AeadCoreError::AuthenticationFailed),
            "a turned-over tag was taken, {length} bytes in"
        );

        // Assert zeroization!
        assert!(
            data.is_zeroized(),
            "the buffer still holds what was deciphered, {length} bytes in"
        );
    }
}

/// The other way round, which is what says the wipe above is the refusal and
/// not something that happens either way.
#[test]
fn test_decrypt_leaves_the_plaintext_when_the_tag_matches() {
    let mut aead = Aegis128L::new();

    for length in LENGTHS {
        let plaintext = vec![0xAB_u8; length];
        let mut data = plaintext.clone();
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&KEY, &NONCE, b"", &mut data, &mut tag);
        aead.decrypt(&KEY, &NONCE, b"", &mut data, &tag)
            .expect("the tag is the one encrypt just wrote");

        assert_eq!(data, plaintext, "{length} bytes in");
    }
}

/// The associated data is not the message, and is left where it was.
///
/// A wipe reaching past the buffer it was given would take the caller's
/// associated data with it, which nothing here owns and nothing here may touch.
#[test]
fn test_decrypt_leaves_the_associated_data_when_it_refuses() {
    let mut aead = Aegis128L::new();
    let aad = vec![0xC3_u8; 64];

    for length in LENGTHS {
        let mut data = vec![0xAB_u8; length];
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&KEY, &NONCE, &aad, &mut data, &mut tag);

        tag[0] ^= 1;

        let refused = aead.decrypt(&KEY, &NONCE, &aad, &mut data, &tag);

        assert_eq!(
            refused,
            Err(AeadCoreError::AuthenticationFailed),
            "a turned-over tag was taken, {length} bytes in"
        );

        assert_eq!(
            aad,
            vec![0xC3_u8; 64],
            "the associated data was written to, {length} bytes in"
        );
    }
}
