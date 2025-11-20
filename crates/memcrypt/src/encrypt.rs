// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroize;

use memcode::MemEncodable;
use memzer::{Secret, Zeroizable, ZeroizationProbe};

use crate::consts::{AAD, TAG_SIZE};
use crate::error::CryptoError;
use crate::guards::EncryptionMemZer;
use crate::{AeadKey, XNonce};

#[derive(PartialEq, Eq, Debug)]
#[allow(unused)]
pub enum EncryptStage {
    MemBytesRequired,
    DrainInto,
    AeadBufferFillWithPlaintext,
    Encrypt,
}

/// Encrypts a MemEncodable value using an in-place, allocation-free pipeline.
///
/// # Safety & Guarantees
/// - **No re-allocations:** Buffers are pre-reserved to their exact sizes.
/// - **Memory hygiene:** On success, the source (`value`) is zeroized and the target buffer is filled.
///   On failure, *all intermediate buffers and keys are zeroized*.
/// - **Ephemeral isolation:** The AEAD key, nonce, and plaintext never coexist in memory once encryption completes.
///
/// # Stages
/// 1. [`MemBytesRequired`] – calculates required buffer size for encoding.
/// 2. [`DrainInto`] – drains the source value into the encoding buffer.
/// 3. [`AeadBufferFillWithPlaintext`] – fills AEAD buffer with plaintext from encoding buffer.
/// 4. [`Encrypt`] – encrypts the encoded bytes with `XChaCha20Poly1305`.
///
/// # Returns
/// The resulting [`Secret<Vec<u8>>`] containing the ciphertext.
///
/// # Errors
/// - [`CryptoError::Overflow`] if the required buffer size calculation overflows.
/// - [`CryptoError::MemEncode`] if the encoding stage fails.
/// - [`CryptoError::AeadBufferNotZeroized`] if the AEAD buffer is not fully zeroized before reserving.
/// - [`CryptoError::InvalidKeyLength`] if the key size is invalid.
pub fn encrypt_mem_encodable<T>(
    aead_key: &mut AeadKey,
    xnonce: &mut XNonce,
    value: &mut T,
) -> Result<Secret<Vec<u8>>, CryptoError>
where
    T: MemEncodable + Zeroize + Zeroizable + ZeroizationProbe,
{
    let mut x = EncryptionMemZer::new(aead_key, xnonce, value);
    encrypt_mem_encodable_with(&mut x, |_, _| {})
}

pub fn encrypt_mem_encodable_with<'a, T, F>(
    x: &mut EncryptionMemZer<'a, T>,
    #[allow(unused)] f: F,
) -> Result<Secret<Vec<u8>>, CryptoError>
where
    T: MemEncodable + Zeroize + Zeroizable + ZeroizationProbe,
    F: Fn(EncryptStage, &mut EncryptionMemZer<'a, T>),
{
    // Stage: MemBytesRequired
    {
        #[cfg(test)]
        f(EncryptStage::MemBytesRequired, x);

        let bytes_required = x.value.mem_bytes_required().map_err(|err| {
            x.zeroize();
            CryptoError::Overflow(err)
        })?;
        x.buf.as_mut().reset_with_capacity(bytes_required);
    }

    // Stage: DrainInto
    {
        #[cfg(test)]
        f(EncryptStage::DrainInto, x);

        x.value.drain_into(x.buf.as_mut()).map_err(|err| {
            x.zeroize();
            CryptoError::MemEncode(err)
        })?;
    }

    // Stage: AeadBufferFillWithPlaintext
    {
        #[cfg(test)]
        f(EncryptStage::AeadBufferFillWithPlaintext, x);

        // Prepare AEAD buffer: reserve space for plaintext + tag
        x.aead_buffer
            .zeroized_reserve_exact(x.buf.as_ref().len() + TAG_SIZE)
            .map_err(|_| {
                x.zeroize();
                CryptoError::AeadBufferNotZeroized
            })?;
        x.aead_buffer
            .drain_slice(x.buf.as_mut().as_mut_slice())
            .expect("Infallible: AeadBuffer has been already reserved with enough capacity");

        // Wipe unused
        x.buf.zeroize();
    }

    // Stage: Encrypt
    {
        #[cfg(test)]
        f(EncryptStage::Encrypt, x);

        let key_slice = &x.aead_key.as_ref().as_slice()[0..x.aead_key_size];

        // wipe unused
        x.aead_key_size.zeroize();

        // SAFETY NOTE: `XChaCha20Poly1305::new_from_slice` creates the cipher from a slice.
        // The `chacha20poly1305` crate is compiled with feature `zeroize`, which ensures
        // the cipher's internal state is zeroized on Drop. We also zeroize our local key buffer.
        let cipher = XChaCha20Poly1305::new_from_slice(key_slice).map_err(|_| {
            x.zeroize();
            CryptoError::InvalidKeyLength
        })?;

        // Wipe key (no longer needed)
        x.aead_key.zeroize();

        cipher
        .encrypt_in_place(x.xnonce.as_ref(), AAD, &mut x.aead_buffer)
        .expect(
            "XChaCha20Poly1305::encrypt is infallible with valid 32-byte aead key and 24-byte xnonce",
        );

        // Wipe nonce (no longer needed)
        drop(cipher);
        x.xnonce.zeroize();
    }

    // Move ciphertext to Secret<Vec<u8>>
    let ciphertext = Secret::from(x.aead_buffer.as_ref().to_vec());
    x.aead_buffer.zeroize();

    Ok(ciphertext)
}
