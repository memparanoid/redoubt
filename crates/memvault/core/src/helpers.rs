// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::AeadApi;
use memcodec::CodecBuffer;
use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::CipherBoxError;
use crate::traits::{Decryptable, Encryptable};

use super::consts::AAD;

#[cfg(test)]
pub(crate) fn to_encryptable_mut_dyn(x: &mut dyn Encryptable) -> &mut dyn Encryptable {
    x
}

#[cfg(test)]
pub(crate) fn to_decryptable_mut_dyn(x: &mut dyn Decryptable) -> &mut dyn Decryptable {
    x
}

#[inline(always)]
pub fn get_sizes<const N: usize>(
    fields: &[&mut dyn Encryptable; N],
) -> Result<[usize; N], CipherBoxError> {
    let mut sizes = [0usize; N];

    for (i, f) in fields.iter().enumerate() {
        sizes[i] = f.mem_bytes_required()?;
    }

    Ok(sizes)
}

#[inline(always)]
pub fn encrypt_into<const N: usize>(
    fields: [&mut dyn Encryptable; N],
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
) -> Result<[Vec<u8>; N], CipherBoxError> {
    let sizes = get_sizes(&fields)?;
    let mut buffers: [CodecBuffer; N] = sizes.map(|s| CodecBuffer::new(s));
    let mut ciphertexts: [Vec<u8>; N] = core::array::from_fn(|_| vec![]);

    encrypt_into_buffers(
        fields,
        aead,
        aead_key,
        nonces,
        tags,
        &mut buffers,
        &mut ciphertexts,
    )?;

    Ok(ciphertexts)
}

#[inline(always)]
fn try_encrypt_into_buffers<const N: usize>(
    mut fields: [&mut dyn Encryptable; N],
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    buffers: &mut [CodecBuffer; N],
    ciphertexts: &mut [Vec<u8>; N],
) -> Result<(), CipherBoxError> {
    for (idx, field) in fields.iter_mut().enumerate() {
        let buf = &mut buffers[idx];

        field.encode_into(buf)?;
        debug_assert!(
            !buf.is_zeroized(),
            "buffer[{}] should contain data after successful encode",
            idx
        );
    }

    for (idx, buf) in buffers.iter_mut().enumerate() {
        ciphertexts[idx] = buf.export_as_vec();
        nonces[idx] = aead.api_generate_nonce()?;
        aead.api_encrypt(
            aead_key,
            &nonces[idx],
            &AAD,
            &mut ciphertexts[idx],
            &mut tags[idx],
        )?;
    }

    Ok(())
}

#[inline(always)]
pub(crate) fn encrypt_into_buffers<const N: usize>(
    fields: [&mut dyn Encryptable; N],
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    buffers: &mut [CodecBuffer; N],
    ciphertexts: &mut [Vec<u8>; N],
) -> Result<(), CipherBoxError> {
    let result =
        try_encrypt_into_buffers(fields, aead, aead_key, nonces, tags, buffers, ciphertexts);

    if result.is_err() {
        buffers.fast_zeroize();
        ciphertexts.fast_zeroize();
        return Err(CipherBoxError::Poisoned);
    }

    Ok(())
}

#[inline(always)]
fn try_decrypt_from<const N: usize>(
    fields: &mut [&mut dyn Decryptable; N],
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    ciphertexts: &mut [Vec<u8>; N],
) -> Result<(), CipherBoxError> {
    for (idx, field) in fields.iter_mut().enumerate() {
        let nonce = &nonces[idx];
        let tag = &tags[idx];
        let ciphertext = &mut ciphertexts[idx];

        aead.api_decrypt(aead_key, nonce, &AAD, ciphertext, tag)?;
        field.decode_from(&mut ciphertext.as_mut_slice())?;
    }

    Ok(())
}

pub fn decrypt_from<const N: usize>(
    fields: &mut [&mut dyn Decryptable; N],
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    ciphertexts: &mut [Vec<u8>; N],
) -> Result<(), CipherBoxError> {
    let result = try_decrypt_from(fields, aead, aead_key, nonces, tags, ciphertexts);

    if result.is_err() {
        ciphertexts.fast_zeroize();
        return Err(CipherBoxError::Poisoned);
    }

    result
}
