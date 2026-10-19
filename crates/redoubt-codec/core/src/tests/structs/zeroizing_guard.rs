// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtArray;
use redoubt_zero::{ZeroizationProbe, ZeroizingGuard};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_zeroizing_guard_codec_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let mut guard = ZeroizingGuard::<RedoubtArray<u8, 5>>::from_default();
    let mut src = [1u8, 2, 3, 4, 5];

    guard.replace_from_mut_array(&mut src);

    let bytes_required = guard.encode_bytes_required()?;
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    guard.encode_into(&mut buf)?;

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = ZeroizingGuard::<RedoubtArray<u8, 5>>::from_default();

    recovered.decode_from(&mut decode_buf.as_mut_slice())?;

    assert_eq!(recovered.as_slice(), &[1, 2, 3, 4, 5]);

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(decode_buf.is_zeroized());
    assert!(guard.is_zeroized());

    Ok(())
}

#[test]
fn test_zeroizing_guard_encodes_as_what_it_holds() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = 0x1234_5678_9abc_def0_u64;
    let mut guard = ZeroizingGuard::from_mut(&mut value);
    let mut bare = 0x1234_5678_9abc_def0_u64;

    let mut guard_buf = RedoubtCodecBuffer::with_capacity(guard.encode_bytes_required()?);
    let mut bare_buf = RedoubtCodecBuffer::with_capacity(bare.encode_bytes_required()?);

    guard.encode_into(&mut guard_buf)?;
    bare.encode_into(&mut bare_buf)?;

    assert_eq!(guard_buf.export_as_vec(), bare_buf.export_as_vec());

    Ok(())
}
