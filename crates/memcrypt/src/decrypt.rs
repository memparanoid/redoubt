// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::Decode;
use memzer::{FastZeroizable, ZeroizationProbe, ZeroizingGuard};

use crate::consts::AAD;
use crate::error::CryptoError;
use crate::guards::DecryptionMemZer;

#[derive(PartialEq, Eq, Debug)]
#[allow(unused)]
pub enum DecryptStage {
    SplitCiphertextAndTag,
    Decrypt,
    Decode,
}

/// Decrypts a Decode value using an in-place, allocation-free pipeline.
///
/// # Safety & Guarantees
/// - **No re-allocations:** Internal buffers are pre-reserved to match ciphertext length.
/// - **Memory hygiene:** On success, the ciphertext, AEAD key, and nonce are all zeroized.
///   On failure, *every intermediate buffer and field is zeroized*.
/// - **Ephemeral isolation:** The decrypted plaintext and AEAD material never coexist
///   in memory after the decryption stage completes.
///
/// # Stages
/// 1. [`NewFromSlice`] – creates the cipher instance from a key slice.
/// 2. [`AeadBufferFillWithCiphertext`] – fills AEAD buffer with ciphertext.
/// 3. [`Decrypt`] – decrypts the ciphertext into the AEAD buffer using `XChaCha20Poly1305`.
/// 4. [`DrainFrom`] – reconstructs `T` by draining data from the decrypted bytes.
///
/// # Returns
/// A [`Secret<T>`] holding the fully reconstructed value `T`.
/// The guard ensures automatic zeroization of `T` upon drop.
///
/// # Errors
/// - [`CryptoError::InvalidKeyLength`] if the key size is invalid.
/// - [`CryptoError::AeadBufferNotZeroized`] if the AEAD buffer is not fully zeroized before reserving.
/// - [`CryptoError::Decrypt`] if AEAD decryption fails.
/// - [`CryptoError::Decode`] if `Decode` fails to reconstruct `T`.
///
/// # Example
///
/// ```
/// use memcrypt::{AeadKey, XNonce, encrypt_mem_encodable, decrypt_mem_decodable};
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
/// // Encrypt sensitive data
/// let mut sensitive_data = vec![6317u64; 20];
/// let mut ciphertext = encrypt_mem_encodable(&mut key, &mut nonce, &mut sensitive_data)?;
///
/// // sensitive_data is guaranteed to be zeroized
/// assert!(sensitive_data.iter().all(|&v| v == 0));
///
/// // Decrypt with same key and nonce
/// let mut key2 = AeadKey::default();
/// let mut key2_material = [197u8; 32];
/// key2.fill_exact(&mut key2_material);
///
/// // key2_material is guaranteed to be zeroized
/// assert!(key2_material.iter().all(|&b| b == 0));
///
/// let mut nonce2 = XNonce::default();
/// let mut nonce2_material = [193u8; 24];
/// nonce2.fill_exact(&mut nonce2_material);
///
/// // nonce2_material is guaranteed to be zeroized
/// assert!(nonce2_material.iter().all(|&b| b == 0));
///
/// let recovered = decrypt_mem_decodable::<Vec<u64>>(&mut key2, &mut nonce2, &mut ciphertext)?;
///
/// // Recovered data matches original
/// assert_eq!(recovered.len(), 20);
/// assert!(recovered.iter().all(|&v| v == 6317));
/// # Ok::<(), memcrypt::CryptoError>(())
/// ```
pub fn decrypt_decodable<T>(
    aead: &mut Aead,
    aead_key: &mut [u8],
    nonce: &mut [u8],
    ciphertext_with_tag: &mut Vec<u8>,
) -> Result<ZeroizingGuard<T>, CryptoError>
where
    T: Default + Decode + FastZeroizable + ZeroizationProbe,
{
    let mut x = DecryptionMemZer::new(aead_key, nonce, ciphertext_with_tag);
    decrypt_mem_decodable_with::<T, _>(aead, &mut x, |_, _| {})
}

pub fn decrypt_mem_decodable_with<T, F>(
    aead: &mut Aead,
    x: &mut DecryptionMemZer,
    #[allow(unused)] f: F,
) -> Result<ZeroizingGuard<T>, CryptoError>
where
    T: Default + Decode + FastZeroizable + ZeroizationProbe,
    F: Fn(DecryptStage, &mut DecryptionMemZer),
{
    // Stage: SplitCiphertextAndTag
    let (mut ciphertext, tag) = {
        #[cfg(test)]
        f(DecryptStage::SplitCiphertextAndTag, x);

        let result =
            memutil::try_split_at_mut_from_end(&mut x.ciphertext_with_tag, aead.tag_size());

        match result {
            Some((ciphertext, tag)) => (ciphertext, tag),
            None => {
                x.fast_zeroize();
                return Err(CryptoError::CiphertextTooShort);
            }
        }
    };

    // Stage: Decrypt
    {
        #[cfg(test)]
        f(DecryptStage::Decrypt, x);

        let aead_key = &mut x.aead_key[0..x.aead_key_size];

        aead.decrypt(aead_key, &x.nonce, AAD, ciphertext, tag)
            .map_err(|e| {
                x.fast_zeroize();
                return CryptoError::Decrypt(e);
            })?;

        // wipe unused
        x.aead_key_size.fast_zeroize();
        x.aead_key.fast_zeroize();
        x.nonce.fast_zeroize();
    }

    // Stage: Decode
    let result = {
        #[cfg(test)]
        f(DecryptStage::Decode, x);

        let mut value = T::default();
        value.decode_from(&mut ciphertext).map_err(|e| {
            x.fast_zeroize();
            return CryptoError::Decode(e);
        })?;

        ZeroizingGuard::new(value)
    };

    Ok(result)
}
