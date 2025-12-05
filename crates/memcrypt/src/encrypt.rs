// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::{BytesRequired, Encode};
use memzer::{FastZeroizable, ZeroizationProbe, ZeroizingGuard};

use crate::consts::AAD;
use crate::error::CryptoError;
use crate::guards::EncryptionMemZer;

#[derive(PartialEq, Eq, Debug)]
#[allow(unused)]
pub enum EncryptStage {
    MemBytesRequired,
    EncodeInto,
    Encrypt,
}

/// Encrypts an Encode value using an in-place, allocation-free pipeline.
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
/// - [`CryptoError::Encode`] if the encoding stage fails.
/// - [`CryptoError::AeadBufferNotZeroized`] if the AEAD buffer is not fully zeroized before reserving.
/// - [`CryptoError::InvalidKeyLength`] if the key size is invalid.
///
/// # Example
///
/// ```
/// use memcrypt::{AeadKey, XNonce, encrypt_mem_encodable};
/// use memzer::ZeroizationProbe;
///
/// let mut key = AeadKey::default();
/// let mut key_material = [197u8; 32];
/// key.fill_exact(&mut key_material);
///
/// // key_material is guaranteed to be zeroized
/// assert!(key_material.iter().all(|&b| b == 0));
///
/// let mut nonce = XNonce::default();
/// let mut nonce_material = [193u8; 24];
/// nonce.fill_exact(&mut nonce_material);
///
/// // nonce_material is guaranteed to be zeroized
/// assert!(nonce_material.iter().all(|&b| b == 0));
///
/// let mut sensitive_data = vec![6317u64; 10];
///
/// let ciphertext = encrypt_mem_encodable(&mut key, &mut nonce, &mut sensitive_data)?;
///
/// // sensitive_data is guaranteed to be zeroized
/// assert!(sensitive_data.is_zeroized());
///
/// // Ciphertext is returned with auto-zeroization
/// assert!(!ciphertext.is_empty());
/// # Ok::<(), memcrypt::CryptoError>(())
/// ```
pub fn encrypt_encodable<T>(
    aead: &mut Aead,
    aead_key: &mut [u8],
    nonce: &mut [u8],
    value: &mut T,
) -> Result<ZeroizingGuard<Vec<u8>>, CryptoError>
where
    T: BytesRequired + Encode + FastZeroizable + ZeroizationProbe,
{
    let mut x = EncryptionMemZer::new(aead_key, nonce, value);
    encrypt_mem_encodable_with(aead, &mut x, |_, _| {})
}

pub fn encrypt_mem_encodable_with<'a, T, F>(
    aead: &mut Aead,
    x: &mut EncryptionMemZer<'a, T>,
    #[allow(unused)] f: F,
) -> Result<ZeroizingGuard<Vec<u8>>, CryptoError>
where
    T: BytesRequired + Encode + FastZeroizable + ZeroizationProbe,
    F: Fn(EncryptStage, &mut EncryptionMemZer<'a, T>),
{
    // Stage: MemBytesRequired
    {
        #[cfg(test)]
        f(EncryptStage::MemBytesRequired, x);

        x.bytes_required = x.value.mem_bytes_required().map_err(|err| {
            x.fast_zeroize();
            CryptoError::Overflow(err)
        })?;
        x.buf
            .realloc_with_capacity(x.bytes_required + aead.tag_size());
    }

    // Stage: EncodeInto
    {
        #[cfg(test)]
        f(EncryptStage::EncodeInto, x);

        x.value.encode_into(&mut x.buf).map_err(|err| {
            x.fast_zeroize();
            CryptoError::Encode(err)
        })?;
    }

    // Stage: Encrypt
    let ciphertext_with_tag = {
        #[cfg(test)]
        f(EncryptStage::Encrypt, x);

        let (plaintext, tag) = memutil::try_split_at_mut(x.buf.as_mut_slice(), x.bytes_required)
            .expect("Infallible: CodecBuffer has been reserved with enough length");
        let aead_key = &mut x.aead_key[0..x.aead_key_size];

        // wipe unused
        x.aead_key_size.fast_zeroize();

        aead.encrypt(aead_key, &mut x.nonce, AAD, plaintext, tag);

        // wipe unused
        x.aead_key.fast_zeroize();
        x.nonce.fast_zeroize();

        let mut ciphertext_with_tag = Vec::new();
        ciphertext_with_tag.reserve_exact(x.bytes_required + aead.tag_size());
        ciphertext_with_tag.extend_from_slice(plaintext);
        ciphertext_with_tag.extend_from_slice(tag);

        x.buf.fast_zeroize();

        ZeroizingGuard::new(ciphertext_with_tag)
    };

    Ok(ciphertext_with_tag)
}
