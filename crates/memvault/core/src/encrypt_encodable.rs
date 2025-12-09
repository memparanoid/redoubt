// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::{BytesRequired, CodecBuffer, Encode};
use memzer::FastZeroizable;

use super::consts::AAD;
use super::error::CryptoError;

#[inline(always)]
pub fn encrypt_encodable<T>(
    aead: &mut Aead,
    aead_key: &[u8],
    nonce: &[u8],
    tag: &mut [u8],
    value: &mut T,
) -> Result<Vec<u8>, CryptoError>
where
    T: BytesRequired + Encode + FastZeroizable,
{
    let bytes_required = value.mem_bytes_required()?;
    let mut buf = CodecBuffer::new(bytes_required);

    value.encode_into(&mut buf)?;
    aead.encrypt(aead_key, nonce, &AAD, buf.as_mut_slice(), tag)?;

    Ok(buf.to_vec())
}
