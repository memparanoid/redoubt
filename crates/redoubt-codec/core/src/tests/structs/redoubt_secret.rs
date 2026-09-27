// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_secret::RedoubtSecret;
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_redoubt_secret_codec_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = 0x1234_5678_9abc_def0_u64;
    let mut secret = RedoubtSecret::from(&mut value);

    let bytes_required = secret.encode_bytes_required()?;
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    secret.encode_into(&mut buf)?;

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = RedoubtSecret::<u64>::default();

    recovered.decode_from(&mut decode_buf.as_mut_slice())?;

    assert_eq!(recovered.as_ref(), &0x1234_5678_9abc_def0);

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(decode_buf.is_zeroized());
    assert!(secret.as_ref().is_zeroized());

    Ok(())
}

#[test]
fn test_redoubt_secret_encodes_as_what_it_holds() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = 0x1234_5678_9abc_def0_u64;
    let mut secret = RedoubtSecret::from(&mut value);
    let mut bare = 0x1234_5678_9abc_def0_u64;

    let mut secret_buf = RedoubtCodecBuffer::with_capacity(secret.encode_bytes_required()?);
    let mut bare_buf = RedoubtCodecBuffer::with_capacity(bare.encode_bytes_required()?);

    secret.encode_into(&mut secret_buf)?;
    bare.encode_into(&mut bare_buf)?;

    assert_eq!(secret_buf.export_as_vec(), bare_buf.export_as_vec());

    Ok(())
}
